# tunnelworm

`tunnelworm` creates direct tunnels between two machines over
[magic-wormhole](https://magic-wormhole.readthedocs.io/).

It started from the ideas behind [fowl](https://github.com/nicr9/fowl), but it now
has its own tunnel-first CLI and adds capabilities that go beyond a single TCP
forward.

## What it is good for

- one-off TCP forwards between two terminals
- named persistent tunnels you can bring back later by name
- remote shell access over an existing tunnel
- stdin/stdout piping over an existing tunnel
- sending files over an existing tunnel
- adding and removing live port forwards on a running tunnel

## Quick start

### One-off TCP forward

On the machine that has the service you want to reach:

```bash
tunnelworm --connect 22
```

That prints a wormhole code. On the other machine:

```bash
tunnelworm --listen 9097 <CODE>
```

Now `127.0.0.1:9097` on the listening side forwards to port `22` on the
connecting side.

### Bare tunnel with no initial forward

If you want a tunnel first and will decide what to do with it later:

```bash
tunnelworm open
```

On the other machine:

```bash
tunnelworm open <CODE>
```

That gives you a live tunnel without forcing an initial port forward.

## Persistent tunnels

Create one named tunnel endpoint on each machine once, then bring it back later
by name.

Creator side:

```bash
tunnelworm tunnel create office
```

Peer side:

```bash
tunnelworm tunnel create laptop --code <CODE>
```

Bring either side back later:

```bash
tunnelworm tunnel up office
tunnelworm tunnel up laptop
```

Inspect and manage saved endpoints:

```bash
tunnelworm tunnel list
tunnelworm tunnel status office
tunnelworm tunnel delete office
```

## Capabilities over a live tunnel

Once a tunnel is up, you can use it for more than port forwarding.

### Shell

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

### Manage live ports

List the active forwards on one tunnel:

```bash
tunnelworm ports office
```

Add one that listens locally and connects on the remote side:

```bash
tunnelworm ports add office --local-listen 9097 --remote-connect 22
```

Remove one by numeric ID:

```bash
tunnelworm ports remove office 1
```

## Compatibility syntax

The preferred interface uses `--listen` and `--connect`, but SSH-style syntax is
still supported for one-off forwards:

```bash
tunnelworm -R 9000:localhost:22
tunnelworm -L 9000:localhost:22 <CODE>
```

## Install and update

Portable binaries are published on this repository's GitHub Releases page.
After installing, you can update in place with:

```bash
tunnelworm self-update
```

## Shell completion

Generate completions for your shell:

```bash
tunnelworm completion zsh
```

Other supported shells include `bash`, `fish`, `elvish`, and `powershell`.
