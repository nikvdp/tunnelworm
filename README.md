# tunnelworm

**Connect two machines peer-to-peer with a short code. Forward ports, get a shell, pipe data, and send files — all over one encrypted tunnel.**

No public IP needed. No SSH keys to exchange. No server to run. One side prints a code, the other side types it in, and the two machines connect peer-to-peer through the tunnel.

Think of it as the tunnelling experience of [chisel](https://github.com/jpillora/chisel) without needing a server, but with a short-code workflow that is easy to start from either side.

---

## Quick start

### Forward a port in two commands

```bash
# machine with the service (e.g. sshd on port 22)
tunnelworm --connect 22

# your machine — type the code that was printed
tunnelworm --listen 9097 <CODE>

# now connect through the tunnel
ssh -p 9097 localhost
```

### Open a bare tunnel and decide later

```bash
# first machine
tunnelworm open

# second machine
tunnelworm open <CODE>
```

The tunnel is live but has no port forward yet. You can use it for anything below.

---

## What you can do with a live tunnel

Every capability here works on **any** live tunnel. Address it by the code printed at connection time. (Named tunnels, covered below, let you use a local name instead.)

### Remote shell

```bash
tunnelworm shell <CODE>
tunnelworm shell <CODE> --command 'uptime'
```

### Pipe stdin / stdout

```bash
echo hello | tunnelworm pipe <CODE>
```

### Send a file

```bash
tunnelworm send-file <CODE> ./report.txt
tunnelworm send-file <CODE> ./report.txt /tmp/inbox/report.txt
```

### Live port management

Add or remove port forwards while the tunnel is already running:

```bash
tunnelworm ports <CODE>
tunnelworm ports add <CODE> --local-listen 9097 --remote-connect 22
tunnelworm ports remove <CODE> 1
```

---

## Named persistent tunnels

One-off tunnels are great for quick tasks. If you connect the same two machines regularly, save the tunnel so you can bring it back by name instead of exchanging a new code each time.

### Create both sides once

```bash
# machine A
tunnelworm tunnel create office

# machine B — use the printed code
tunnelworm tunnel create laptop --code <CODE>
```

You can include an initial port forward at creation time:

```bash
tunnelworm tunnel create office --connect 22
tunnelworm tunnel create laptop --listen 9097 --code <CODE>
```

### Bring it up later by name

```bash
tunnelworm tunnel up office    # on machine A
tunnelworm tunnel up laptop    # on machine B
```

### Use the named tunnel like any other

```bash
tunnelworm shell office
echo hello | tunnelworm pipe office
tunnelworm send-file office ./data.csv
tunnelworm ports add office --local-listen 8080 --remote-connect 80
```

### Manage saved tunnels

```bash
tunnelworm tunnel list
tunnelworm tunnel status office
tunnelworm tunnel delete office
```

---

## SSH-style compatibility

If you already think in `-L` / `-R`, that works too:

```bash
tunnelworm -R 9000:localhost:22
tunnelworm -L 9000:localhost:22 <CODE>
```

`-L` on one side always needs a corresponding `-R` on the other.

---

## Install and update

Download a release binary from this repository's GitHub Releases page.

Update in place:

```bash
tunnelworm self-update
```

### Shell completion

```bash
tunnelworm completion zsh
```

Supported shells: `bash`, `zsh`, `fish`, `elvish`, `powershell`.

---

## Background

tunnelworm uses [magic-wormhole](https://magic-wormhole.readthedocs.io/) under the hood to establish the connection between the two sides and provide the short human-readable codes.

The project grew out of the ideas behind [fowl](https://github.com/nicr9/fowl) but is now its own tool with a tunnel-first design: the tunnel is the primitive, and forwarding, shells, pipes, and file transfer are all capabilities layered on top of it.
