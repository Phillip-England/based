package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"github.com/phillip-england/based/internal/db"
	"github.com/phillip-england/based/internal/tmux"
	"github.com/yuin/goldmark"
)

type Options struct {
	Addr          string
	DBPath        string
	AdminUsername string
	AdminPassword string
}

type Server struct {
	http          *http.Server
	store         *db.AuthStore
	adminUsername string
	adminPassword string
	upgrader      websocket.Upgrader
}

type terminalMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

func New(opts Options) (*Server, error) {
	store, err := db.Open(opts.DBPath)
	if err != nil {
		return nil, err
	}
	s := &Server{
		store:         store,
		adminUsername: opts.AdminUsername,
		adminPassword: opts.AdminPassword,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					return true
				}
				u, err := url.Parse(origin)
				return err == nil && u.Host == r.Host
			},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.requireAuth(s.home))
	mux.HandleFunc("/guide", s.requireAuth(s.guide))
	mux.HandleFunc("/login", s.login)
	mux.HandleFunc("/logout", s.logout)
	mux.HandleFunc("/sessions", s.requireAuth(s.createSession))
	mux.HandleFunc("/terminal/", s.requireAuth(s.terminal))
	mux.HandleFunc("/ws/", s.requireAuth(s.terminalWS))
	s.http = &http.Server{
		Addr:              opts.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

func (s *Server) Close() error {
	return s.store.Close()
}

func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.http.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	now := time.Now()
	if banned, until, err := s.store.IsBanned(ip, now); err != nil {
		http.Error(w, "auth store error", http.StatusInternalServerError)
		return
	} else if banned {
		w.WriteHeader(http.StatusTooManyRequests)
		loginTemplate.Execute(w, map[string]string{"Error": "This IP is banned until " + until.Local().Format(time.RFC1123)})
		return
	}

	if r.Method == http.MethodGet {
		loginTemplate.Execute(w, nil)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("a")
	password := r.FormValue("b")
	matrix := r.FormValue("c")
	if s.validCredentials(username, password, matrix) {
		if err := s.store.RecordSuccess(ip, now); err != nil {
			http.Error(w, "auth store error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "based_session",
			Value:    s.sessionCookieValue(now.Add(24 * time.Hour)),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   86400,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	banned, until, err := s.store.RecordFailure(ip, now)
	if err != nil {
		http.Error(w, "auth store error", http.StatusInternalServerError)
		return
	}
	if banned {
		w.WriteHeader(http.StatusTooManyRequests)
		loginTemplate.Execute(w, map[string]string{"Error": "Too many failures. This IP is banned until " + until.Local().Format(time.RFC1123)})
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	loginTemplate.Execute(w, map[string]string{"Error": "Invalid username or password"})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "based_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	sessions, err := tmux.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	homeTemplate.Execute(w, sessions)
}

func (s *Server) guide(w http.ResponseWriter, r *http.Request) {
	guideTemplate.Execute(w, map[string]template.HTML{"Content": renderMarkdown(adminGuideMarkdown)})
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if err := tmux.Create(r.Context(), name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) terminal(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/terminal/")
	terminalTemplate.Execute(w, name)
}

func (s *Server) terminalWS(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/ws/")
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	attachCtx, cancelAttach := context.WithCancel(context.Background())
	defer cancelAttach()

	cmd := tmux.AttachCommand(attachCtx, name)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte(err.Error()))
		return
	}
	defer detachTerminal(name, ptmx, cmd)

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				if writeErr := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				_ = conn.WriteJSON(terminalMessage{Type: "ended"})
				return
			}
		}
	}()

	for {
		typ, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		switch typ {
		case websocket.BinaryMessage:
			if _, err := ptmx.Write(msg); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				return
			}
		case websocket.TextMessage:
			var message terminalMessage
			if err := json.Unmarshal(msg, &message); err == nil && message.Type != "" {
				switch message.Type {
				case "input":
					if _, err := ptmx.Write([]byte(message.Data)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
						return
					}
				case "resize":
					if message.Cols > 0 && message.Rows > 0 {
						_ = pty.Setsize(ptmx, &pty.Winsize{Cols: message.Cols, Rows: message.Rows})
					}
				case "detach":
					return
				}
			} else if _, err := ptmx.Write(msg); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				return
			}
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

func detachTerminal(name string, ptmx io.Closer, cmd interface {
	Wait() error
}) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tmux.Detach(ctx, name)
	_ = ptmx.Close()

	waitCh := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
	case <-time.After(2 * time.Second):
	}
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("based_session")
		if err != nil || !s.validSessionCookie(cookie.Value, time.Now()) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) validCredentials(username, password, matrix string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(s.adminUsername)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(s.adminPassword)) == 1
	matrixOK := subtle.ConstantTimeCompare([]byte(matrix), []byte("258")) == 1
	return userOK && passOK && matrixOK
}

func (s *Server) sessionCookieValue(expires time.Time) string {
	exp := strconv.FormatInt(expires.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(s.adminPassword))
	mac.Write([]byte(s.adminUsername))
	mac.Write([]byte(":"))
	mac.Write([]byte(exp))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return exp + "." + sig
}

func (s *Server) validSessionCookie(value string, now time.Time) bool {
	expRaw, sig, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	expUnix, err := strconv.ParseInt(expRaw, 10, 64)
	if err != nil {
		return false
	}
	if now.After(time.Unix(expUnix, 0)) {
		return false
	}
	expected := s.sessionCookieValue(time.Unix(expUnix, 0))
	_, expectedSig, ok := strings.Cut(expected, ".")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sig), []byte(expectedSig)) == 1
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var loginTemplate = template.Must(template.New("login").Parse(page("Login", `
<main class="login">
  <form method="post" action="/login" autocomplete="off">
    {{with .Error}}<p class="error">{{.}}</p>{{end}}
    <input name="a" autocomplete="off" autofocus>
    <input name="b" type="password" autocomplete="off">
    <input id="c" name="c" type="hidden">
    <div class="matrix">
      <button type="button" aria-pressed="false"></button>
      <button type="button" aria-pressed="false"></button>
      <button type="button" aria-pressed="false"></button>
      <button type="button" aria-pressed="false"></button>
      <button type="button" aria-pressed="false"></button>
      <button type="button" aria-pressed="false"></button>
      <button type="button" aria-pressed="false"></button>
      <button type="button" aria-pressed="false"></button>
      <button type="button" aria-pressed="false"></button>
    </div>
    <button type="submit">Continue</button>
  </form>
</main>
<script>
const selected = new Set();
const matrixValue = document.getElementById('c');
document.querySelectorAll('.matrix button').forEach((button, index) => {
  button.addEventListener('click', () => {
    const cell = String(index + 1);
    if (selected.has(cell)) {
      selected.delete(cell);
      button.classList.remove('active');
      button.setAttribute('aria-pressed', 'false');
    } else {
      selected.add(cell);
      button.classList.add('active');
      button.setAttribute('aria-pressed', 'true');
    }
    matrixValue.value = Array.from(selected).sort().join('');
  });
});
</script>`)))

var homeTemplate = template.Must(template.New("home").Parse(page("Sessions", `
<header><h1>based</h1><nav><a href="/guide">Guide</a><a href="/logout">Log out</a></nav></header>
<main>
  <form class="new-session" method="post" action="/sessions">
    <input name="name" placeholder="session-name" pattern="[A-Za-z0-9_.:-]+" required>
    <button type="submit">New session</button>
  </form>
  <section class="sessions">
    {{range .}}
      <a class="session" href="/terminal/{{.Name}}">
        <strong>{{.Name}}</strong>
        <span>{{.Windows}} windows</span>
      </a>
    {{else}}
      <p class="empty">No tmux sessions are running.</p>
    {{end}}
  </section>
</main>`)))

var guideTemplate = template.Must(template.New("guide").Parse(page("Guide", `
<header><h1>based</h1><nav><a href="/">Sessions</a><a href="/logout">Log out</a></nav></header>
<main>
  <article class="markdown">{{.Content}}</article>
</main>`)))

var terminalTemplate = template.Must(template.New("terminal").Parse(page("Terminal", `
<main class="terminal-page" aria-label="tmux session {{.}}">
  <button id="detach" class="detach" type="button" title="Detach and leave this tmux session running">Detach</button>
  <div id="terminal"></div>
</main>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm/css/xterm.css">
<script src="https://cdn.jsdelivr.net/npm/xterm/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit/lib/xterm-addon-fit.js"></script>
<script>
const terminalElement = document.getElementById('terminal');
const detachButton = document.getElementById('detach');
const term = new Terminal({
  cursorBlink: true,
  fontSize: 14,
  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace',
  theme: {
    background: '#000000',
    foreground: '#ffffff',
    cursor: '#00d1ff',
    selectionBackground: '#00d1ff',
    selectionForeground: '#000000'
  }
});
const fitAddon = new FitAddon.FitAddon();
term.loadAddon(fitAddon);
term.open(terminalElement);
const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws = new WebSocket(proto + '//' + location.host + '/ws/{{.}}');
ws.binaryType = 'arraybuffer';
ws.onmessage = event => {
  if (typeof event.data === 'string') {
    try {
      const message = JSON.parse(event.data);
      if (message.type === 'ended') {
        location.href = '/';
        return;
      }
    } catch (_) {}
    term.write(event.data);
    return;
  }
  term.write(new Uint8Array(event.data));
};
ws.onclose = () => {
  location.href = '/';
};
const sendMessage = message => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify(message));
detachButton.addEventListener('click', () => {
  sendMessage({type: 'detach'});
  detachButton.disabled = true;
});
const fit = () => {
  fitAddon.fit();
  sendMessage({type: 'resize', cols: term.cols, rows: term.rows});
};
term.onData(data => sendMessage({type: 'input', data}));
ws.addEventListener('open', fit);
window.addEventListener('resize', fit);
requestAnimationFrame(fit);
term.focus();
</script>`)))

func page(title, body string) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
:root{--bg:#000;--panel:#050505;--text:#fff;--muted:#a3a3a3;--border:#262626;--accent:#00d1ff}*{box-sizing:border-box}html,body{min-height:100%%}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.5}a{color:var(--text)}a:hover{color:var(--accent)}header{height:64px;display:flex;align-items:center;justify-content:space-between;padding:0 24px;border-bottom:1px solid var(--border);background:var(--bg)}nav{display:flex;align-items:center;gap:16px}h1{font-size:20px;margin:0}.login{min-height:100vh;display:grid;place-items:center;padding:24px}.login form{width:min(320px,100%%);display:grid;gap:12px}.error{border:1px solid var(--accent);color:var(--text);padding:12px;border-radius:8px;margin:0}label{display:grid;gap:6px;color:var(--muted)}input{width:100%%;background:var(--panel);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:12px;font:inherit}input:focus{outline:2px solid var(--accent);outline-offset:2px}button{background:var(--accent);color:#000;border:0;border-radius:8px;padding:12px 16px;font:inherit;font-weight:700;cursor:pointer}button:disabled{opacity:.6;cursor:default}.matrix{display:grid;grid-template-columns:repeat(3,34px);gap:3px;justify-content:center;margin:4px 0}.matrix button{width:34px;height:34px;border:1px solid var(--border);border-radius:2px;background:var(--panel);padding:0}.matrix button.active{background:#d40000;border-color:#ff3030}main{width:min(960px,100%%);margin:0 auto;padding:24px}.new-session{display:flex;gap:12px;margin-bottom:24px}.new-session input{flex:1}.sessions{display:grid;gap:12px}.session{display:flex;align-items:center;justify-content:space-between;text-decoration:none;background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px}.session:hover{border-color:var(--accent);color:var(--text)}.session span,.empty{color:var(--muted)}.markdown{max-width:760px}.markdown h1{font-size:32px;margin:0 0 16px}.markdown h2{font-size:22px;margin:32px 0 10px}.markdown p,.markdown ul,.markdown ol{color:#e5e5e5}.markdown li{margin:6px 0}.markdown code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:2px 5px}.markdown pre{overflow:auto;background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px}.markdown pre code{background:transparent;border:0;border-radius:0;padding:0}.terminal-page{position:relative;width:100vw;height:100vh;margin:0;padding:10px;overflow:hidden}.detach{position:absolute;right:18px;top:18px;z-index:2;padding:8px 10px;background:rgba(0,209,255,.9)}#terminal{width:100%%;height:100%%;background:var(--bg)}#terminal .xterm{height:100%%}.xterm .xterm-viewport{background:var(--bg) !important}@media(max-width:640px){header{padding:0 16px}.new-session{display:grid}}
</style>
</head>
<body>%s</body>
</html>`, title, body)
}

func renderMarkdown(source string) template.HTML {
	var out bytes.Buffer
	if err := goldmark.Convert([]byte(source), &out); err != nil {
		return template.HTML(template.HTMLEscapeString(source))
	}
	return template.HTML(out.String())
}

var adminGuideMarkdown = strings.Join([]string{
	"# Admin guide",
	"",
	"based uses tmux for the terminal workspace. Each browser terminal attaches to a tmux session, so panes, windows, and detach behavior use tmux's normal controls.",
	"",
	"## Sessions",
	"",
	"Create a session from the admin portal, then open it from the session list. A session keeps running after you leave the browser terminal.",
	"",
	"Use the Detach button when you want to leave the browser terminal without stopping the shell or any running command. Closing the tab also detaches the browser client.",
	"",
	"## Split the terminal into panes",
	"",
	"Tmux commands start with the prefix key:",
	"",
	"```text",
	"Ctrl-b",
	"```",
	"",
	"After pressing the prefix, press one of these keys:",
	"",
	"```text",
	"%    split left and right",
	"\"    split top and bottom",
	"```",
	"",
	"Examples:",
	"",
	"```text",
	"Ctrl-b %",
	"Ctrl-b \"",
	"```",
	"",
	"## Move between panes",
	"",
	"```text",
	"Ctrl-b arrow-key",
	"Ctrl-b o",
	"```",
	"",
	"Use arrow keys to move in a direction. Use `Ctrl-b o` to cycle through panes.",
	"",
	"## Resize panes",
	"",
	"```text",
	"Ctrl-b Ctrl-arrow-key",
	"```",
	"",
	"Hold `Ctrl` with an arrow key after the tmux prefix to resize the active pane.",
	"",
	"## Windows",
	"",
	"Windows are separate full terminal layouts inside the same session.",
	"",
	"```text",
	"Ctrl-b c    create a window",
	"Ctrl-b n    next window",
	"Ctrl-b p    previous window",
	"Ctrl-b w    choose a window",
	"```",
	"",
	"## Detach and return later",
	"",
	"```text",
	"Ctrl-b d",
	"```",
	"",
	"This detaches from tmux and leaves the session running. Reopen the session from the admin portal to continue where you left off.",
}, "\n")
