package server

import (
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

	username := r.FormValue("username")
	password := r.FormValue("password")
	if s.validCredentials(username, password) {
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

	cmd := tmux.AttachCommand(r.Context(), name)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte(err.Error()))
		return
	}
	defer ptmx.Close()
	defer cmd.Process.Kill()

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

func (s *Server) validCredentials(username, password string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(s.adminUsername)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(s.adminPassword)) == 1
	return userOK && passOK
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
  <form method="post" action="/login">
    <h1>based</h1>
    {{with .Error}}<p class="error">{{.}}</p>{{end}}
    <label>Username<input name="username" autocomplete="username" autofocus></label>
    <label>Password<input name="password" type="password" autocomplete="current-password"></label>
    <button type="submit">Log in</button>
  </form>
</main>`)))

var homeTemplate = template.Must(template.New("home").Parse(page("Sessions", `
<header><h1>based</h1><a href="/logout">Log out</a></header>
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

var terminalTemplate = template.Must(template.New("terminal").Parse(page("Terminal", `
<main class="terminal-page" aria-label="tmux session {{.}}"><div id="terminal"></div></main>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm/css/xterm.css">
<script src="https://cdn.jsdelivr.net/npm/xterm/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit/lib/xterm-addon-fit.js"></script>
<script>
const terminalElement = document.getElementById('terminal');
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
ws.onmessage = event => term.write(new Uint8Array(event.data));
const sendMessage = message => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify(message));
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
:root{--bg:#000;--panel:#050505;--text:#fff;--muted:#a3a3a3;--border:#262626;--accent:#00d1ff}*{box-sizing:border-box}html,body{min-height:100%%}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:var(--text)}a:hover{color:var(--accent)}header{height:64px;display:flex;align-items:center;justify-content:space-between;padding:0 24px;border-bottom:1px solid var(--border);background:var(--bg)}h1{font-size:20px;margin:0}.login{min-height:100vh;display:grid;place-items:center;padding:24px}.login form{width:min(380px,100%%);display:grid;gap:16px}.login h1{font-size:32px}.error{border:1px solid var(--accent);color:var(--text);padding:12px;border-radius:8px;margin:0}label{display:grid;gap:6px;color:var(--muted)}input{width:100%%;background:var(--panel);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:12px;font:inherit}input:focus{outline:2px solid var(--accent);outline-offset:2px}button{background:var(--accent);color:#000;border:0;border-radius:8px;padding:12px 16px;font:inherit;font-weight:700;cursor:pointer}main{width:min(960px,100%%);margin:0 auto;padding:24px}.new-session{display:flex;gap:12px;margin-bottom:24px}.new-session input{flex:1}.sessions{display:grid;gap:12px}.session{display:flex;align-items:center;justify-content:space-between;text-decoration:none;background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px}.session:hover{border-color:var(--accent);color:var(--text)}.session span,.empty{color:var(--muted)}.terminal-page{width:100vw;height:100vh;margin:0;padding:10px;overflow:hidden}#terminal{width:100%%;height:100%%;background:var(--bg)}#terminal .xterm{height:100%%}.xterm .xterm-viewport{background:var(--bg) !important}@media(max-width:640px){header{padding:0 16px}.new-session{display:grid}}
</style>
</head>
<body>%s</body>
</html>`, title, body)
}
