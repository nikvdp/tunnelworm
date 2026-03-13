# tunnelworm

A Rust CLI for TCP tunnels over [magic-wormhole](https://magic-wormhole.readthedocs.io/).

tunnelworm started as a Rust reimplementation of [fowl](https://github.com/nicr9/fowl) and has since become a more opinionated tool with its own CLI shape. The main addition is named persistent tunnels: create a tunnel endpoint once, save it locally, and bring it back later by name.

## Use cases

- One-off port forwards between two terminals
- Named persistent tunnels that survive process restarts
- Sharing local TCP services like SSH, HTTP, and Postgres between machines

## Quick examples

### One-off tunnel

```bash
# service side
tunnelworm --connect 22

# client side (use the printed code)
tunnelworm --listen 9097 <CODE>
```

### Named persistent tunnel

```bash
# service side
tunnelworm tunnel create office-ssh --connect 22

# client side (use the printed code)
tunnelworm tunnel create laptop-ssh --listen 9097 --code <CODE>

# later, bring either side back by name
tunnelworm tunnel up office-ssh
tunnelworm tunnel up laptop-ssh
```

### Shell completions

```bash
tunnelworm completion zsh   # also: bash, fish
```

## Persistent tunnel commands

| Command | Description |
|---------|-------------|
| `tunnel create` | Create and save a named tunnel endpoint |
| `tunnel up` | Bring a saved tunnel back up |
| `tunnel status` | Show the state of a tunnel |
| `tunnel list` | List all saved tunnels |
| `tunnel delete` | Remove a saved tunnel |

## Relationship to fowl

tunnelworm is based on fowl's idea and protocol surface but is not a straight clone. The CLI, persistent tunnel lifecycle, and operator UX are intentionally different.
