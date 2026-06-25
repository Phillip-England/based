# based

`based` is a small authenticated web UI for creating and attaching to local tmux sessions.

## Run

Set credentials once:

```sh
based set-credentials -username admin -password secret
```

Start the server:

```sh
based serve
```

Open `http://localhost:37491`, log in, create a session, and open it from the session list.

## Detach without killing the shell

Terminal pages include a `Detach` button in the top-right corner. Use it when you want to leave the browser terminal but keep the tmux session, shell, and running commands alive.

Detaching returns you to the session list. Reopen the same session later to continue exactly where you left off.

Closing the browser tab or losing the WebSocket connection also detaches the web client from tmux instead of killing the shell process.

Inside the terminal, tmux's normal detach key binding still works too:

```text
Ctrl-b d
```

That key sequence detaches from tmux and leaves the session running.
