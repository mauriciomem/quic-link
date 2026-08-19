# Platform notes (Linux & macOS)

*This page is meant to be kept reasonably current, but it
might drift a little behind the code. If something here does not match what you see,
the CLI's own `--help` output is the final word.*

## Binding well-known UDP ports

Ports below 1024 require elevated privileges on both Linux and macOS.

- **Use a port at or above 1024.** Run the agent with `--listen :4443`, or any
  other high port; no privilege is needed and nothing has to be granted. This is
  the supported answer.
- **On Linux you can grant the capability yourself**, if you have a reason to want
  a low port:

  ```bash
  sudo setcap 'cap_net_bind_service=+ep' ./quic-link
  ```

  This works, and quic-link neither needs nor asks for it. Know the trade-off
  before you rely on it: the capability is attached to the file, so **replacing the
  binary silently removes it** — every upgrade, every rebuild. The bind then fails
  with a permission error that looks like a bug rather than a missing grant.
  There is no macOS equivalent; on macOS, use a high port.

The same applies to the client side in reverse mode. A `[servers.<name>]` block with
`listen` set binds a port on the workstation, and a port below 1024 is refused there
for the same reason and with the same remedy: choose 1024 or above. quic-link will
not ask you to run it as root, because that would put the long-lived identity key
inside a privileged process to solve a problem a different port also solves.

## UDP receive buffer

The QUIC library warns at startup if it can't raise the UDP receive buffer to
around 7 MB. This is a performance advisory only; the tunnel still works without
it. To raise the limit:

- **Linux:**
  ```bash
  sudo sysctl -w net.core.rmem_max=7340032 net.core.rmem_default=7340032
  ```
  Add both lines to `/etc/sysctl.conf` to make the change persist across reboots.
- **macOS:**
  ```bash
  sudo sysctl -w kern.ipc.maxsockbuf=7340032
  ```

## macOS Local Network permission (macOS 15 Sequoia and later)

macOS 15 and later silently drop unicast traffic to LAN addresses (`192.168.x.x`,
`10.x.x.x`, and similar) until the app making the connection is granted **Local
Network** access. This does not show up as a permission prompt failure; it shows
up as a plain timeout, which makes the tool look broken even though the network is
fine.

**Symptom:** `daemon` or `ping` against a LAN agent hangs and then fails with:

```
timeout: no recent network activity
```

**Fix:**

1. Open **System Settings → Privacy & Security → Local Network**.
2. Grant access to whatever terminal app you're running quic-link from (Terminal,
   iTerm, VS Code's integrated terminal, etc.).
3. Re-run the command.

If you want to confirm this is actually the cause before digging further, running
the same command under `sudo` bypasses the check; if that suddenly works, this is
the reason.
