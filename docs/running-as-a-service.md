# Running quic-link as a service

*This page is meant to be kept reasonably current, but it might drift a little behind the
code. If something here does not match what you see, the CLI's own `--help` output is the
final word.*

`quic-link daemon` runs in the **foreground** and stays there. Backgrounding it, restarting
it and starting it at login are your service manager's job, not the binary's — so quic-link
does not write, install or manage a service file, and never will. What follows are reference
files you copy, adapt and own.

**Why it works this way.** The daemon is deliberately supervisor-agnostic: it takes no
privilege, holds exactly one instance per user, reclaims its own socket after an unclean
exit, and treats `SIGINT` and `SIGTERM` identically with a bounded drain. Any supervisor can
background a foreground process, so encoding "background" as a second command would add a
distinction that does not exist. The consequence, which is the point: **the file below is
yours.** You can edit, version and audit it, and an upgrade of quic-link cannot silently
change how your machine starts it.

If you would rather not run it as a service at all, you do not have to. `quic-link daemon &`
in a terminal, or a `tmux` window, is a perfectly ordinary way to use it.

---

## Before you start

The daemon needs two things to be useful:

1. **An identity** — `quic-link keygen`, once per machine.
2. **At least one server to reach.** Either a settings file at
   `~/.config/quic-link/config.toml`, or the server flags on the command line. Three lines is
   enough for a file:

   ```toml
   [servers.web1]
   addr = "server.example.net:7443"
   pin  = "<the agent's pin>"
   ```

Check both with `quic-link doctor` before wiring anything into a service manager. Diagnosing
a service that will not start is harder than diagnosing a command that will not run.

---

## Linux — a systemd **user** service

A *user* service, not a system one. It runs as you, needs no root, and finds your identity
key and settings in your own home directory. A system service running as `root` would look
for both in root's home and find neither.

Write `~/.config/systemd/user/quic-link.service`:

```ini
[Unit]
Description=quic-link client daemon
Documentation=https://github.com/mauriciomem/quic-link
# Only ordering, not a requirement: the daemon retries on its own if the
# network is not ready yet, so a boot with no network is not a failure.
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/quic-link daemon
# The daemon reclaims a stale socket on its own, so a restart after an unclean
# exit needs no cleanup step.
Restart=on-failure
RestartSec=5s
# It drains in well under a second normally and bounds itself at 30 seconds in
# the worst case, so give it more than that before SIGKILL. Cutting a drain
# short resets live connections that were about to close cleanly.
TimeoutStopSec=45s

[Install]
WantedBy=default.target
```

Adjust `ExecStart` to wherever your binary is — `%h` is your home directory, and systemd
requires an absolute path (no `PATH` lookup, no `~`).

Then:

```bash
systemctl --user daemon-reload
systemctl --user enable --now quic-link.service
systemctl --user status quic-link.service
journalctl --user -u quic-link.service -f      # its logs
```

**To have it run before you log in**, and keep running after you log out:

```bash
sudo loginctl enable-linger "$USER"
```

Without lingering, a user service starts at your first login and stops with your last
session. That is often what you want on a laptop and rarely what you want on a server.

**Scoping to one server** — add the flag to `ExecStart`:

```ini
ExecStart=%h/.local/bin/quic-link daemon --server web1
```

---

## macOS — a launchd **LaunchAgent**

A LaunchAgent (per-user, `~/Library/LaunchAgents/`), not a LaunchDaemon (system-wide, runs as
root). The same reasoning as above: it must run as you to find your key.

Write `~/Library/LaunchAgents/io.quic-link.daemon.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.quic-link.daemon</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/quic-link</string>
        <string>daemon</string>
    </array>

    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>/tmp/quic-link.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/quic-link.log</string>
</dict>
</plist>
```

Use an absolute path in `ProgramArguments`: launchd does not consult your shell's `PATH`.

```bash
launchctl load  ~/Library/LaunchAgents/io.quic-link.daemon.plist
launchctl list | grep quic-link
launchctl unload ~/Library/LaunchAgents/io.quic-link.daemon.plist
```

### One thing to watch on macOS

**A launchd job does not inherit your shell's environment**, and the daemon chooses where to
put its control socket from the environment:

1. `$XDG_RUNTIME_DIR/quic-link/daemon.sock`, when `XDG_RUNTIME_DIR` is set
2. `$TMPDIR/quic-link-<uid>/daemon.sock`, when `TMPDIR` is set and the path is short enough
3. `/tmp/quic-link-<uid>/daemon.sock`

A systemd user service is given `XDG_RUNTIME_DIR`, so on Linux this settles itself. Under
launchd neither variable necessarily matches what your terminal has, so the daemon and your
interactive `quic-link status` can pick **different** paths — and `status` then reports that no
daemon is running while one is.

If that happens, pin the choice explicitly in the plist so both agree:

```xml
    <key>EnvironmentVariables</key>
    <dict>
        <key>TMPDIR</key>
        <string>/tmp</string>
    </dict>
```

and confirm with `quic-link status` in a terminal. *This behaviour is described from reading
the socket-path selection code; it has not been verified on macOS hardware. If you find it
behaves differently, the code is the final word — please say so.*

---

## Checking it worked

```bash
quic-link status          # the fleet and each session's state
quic-link doctor          # settings, identity, resolver, and a real lookup
```

`quic-link status` reporting "daemon is not running" while your service manager says it is
running almost always means the two disagree about the socket path — see the macOS note above.

## Stopping and removing it

```bash
# Linux
systemctl --user disable --now quic-link.service
rm ~/.config/systemd/user/quic-link.service
systemctl --user daemon-reload

# macOS
launchctl unload ~/Library/LaunchAgents/io.quic-link.daemon.plist
rm ~/Library/LaunchAgents/io.quic-link.daemon.plist
```

These files are yours, so removing them is your business: `quic-link init --undo` removes only
what quic-link itself installed, which is the one resolver file and nothing else.
