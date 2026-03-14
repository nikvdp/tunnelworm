# tunnelworm

`tunnelworm` creates direct tunnels between two machines over
[magic-wormhole](https://magic-wormhole.readthedocs.io/).

It grew out of the ideas behind [fowl](https://github.com/nicr9/fowl), but is
now its own tool with a tunnel-first design.

The core idea is simple: a tunnel connects two machines. TCP forwarding is just
one thing you can do over that tunnel. Shells, pipes, file transfer, and live
port changes all work over the same connection too.

## Two ways to create a tunnel

### One-off tunnels

Use the top-level command for a temporary tunnel that lasts one session.

Forward a TCP port directly:

```bash
# machine with the service
tunnelworm --connect 22

# other machine, using the printed code
tunnelworm --listen 9097 <CODE>
```

Or open a bare tunnel first and decide what to do with it after it connects:

```bash
# first side
tunnelworm open

# second side
tunnelworm open <CODE>
```

### Named persistent tunnels

Use `tunnelworm tunnel` when you want to save an endpoint locally and bring it
back later by name.

```bash
# creator side
tunnelworm tunnel create office

# peer side, using the printed code
tunnelworm tunnel create laptop --code <CODE>

# later, on each machine
tunnelworm tunnel up office
tunnelworm tunnel up laptop
```

Manage saved endpoints:

```bash
tunnelworm tunnel list
tunnelworm tunnel status office
tunnelworm tunnel delete office
```

## What you can do with any live tunnel

Every capability below works with both one-off and named tunnels. For a named
endpoint, use its local name. For a live one-off tunnel, you can use its code.

### TCP port forwarding

Set up a forward at creation time:

```bash
# service side
tunnelworm --connect 22

# client side
tunnelworm --listen 9097 <CODE>
```

Or add and remove forwards while a tunnel is running:

```bash
tunnelworm ports office
tunnelworm ports add office --local-listen 9097 --remote-connect 22
tunnelworm ports remove office 1
```

### Remote shell

```bash
tunnelworm shell office
tunnelworm shell office --command 'pwd'
```

### Pipe stdin/stdout

```bash
echo hello | tunnelworm pipe office
```

### Send a file

```bash
tunnelworm send-file office ./report.txt
tunnelworm send-file office ./report.txt /tmp/inbox/report.txt
```

## Quick examples

### Forward SSH from another machine

```bash
# machine with sshd
tunnelworm --connect 22

# your machine
tunnelworm --listen 9097 <CODE>
ssh -p 9097 localhost
```

### Open a tunnel, then get a shell with no port forward

```bash
# first side
tunnelworm open

# second side
tunnelworm open <CODE>

# either side, while the tunnel is live
tunnelworm shell <CODE>
```

### Send a file over a named tunnel

```bash
tunnelworm send-file office ./report.txt
```

## Compatibility syntax

The preferred interface uses `--listen` and `--connect`, but SSH-style flags
are also accepted for one-off forwarding:

```bash
tunnelworm -R 9000:localhost:22
tunnelworm -L 9000:localhost:22 <CODE>
```

## Install and update

Download a release binary for your platform from GitHub Releases.

Update in place:

```bash
tunnelworm self-update
```

## Shell completion

```bash
tunnelworm completion zsh
```

Supported shells: `bash`, `zsh`, `fish`, `elvish`, and `powershell`.
