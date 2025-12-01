# NFTablesEx.Port

Port component for [NFTablesEx](https://github.com/yourusername/nftables_ex). Provides a Zig-based native port executable for communicating with Linux nftables via the official libnftables JSON API.

## Overview

NFTablesEx.Port is the low-level communication layer that bridges Elixir and the Linux kernel's nftables firewall. It provides:

- **Native Zig Port Executable** - High-performance port process with `CAP_NET_ADMIN` capability
- **JSON Communication** - Uses the official nftables JSON API via libnftables
- **Automatic Framing** - 4-byte length-prefixed packets for reliable communication
- **Process Isolation** - Port process crashes don't affect the Elixir VM
- **Synchronous API** - Simple request/response pattern with timeout support

## Architecture

```
NFTablesEx (High-level Elixir API)
         ↓
NFTablesEx.Port (GenServer)
         ↓
Erlang Port (Zig executable)
         ↓
libnftables (C library)
         ↓
Linux Kernel (nftables)
```

## Installation

Add `nftables_ex_port` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:nftables_ex_port, "~> 0.4.0"}
  ]
end
```

## Requirements

- **Linux kernel** with nftables support (kernel 3.13+)
- **libnftables** library installed (`nftables` package on most distros)
- **Zig compiler** (for building from source)
- **CAP_NET_ADMIN** capability on the port executable

### Setting Capabilities

The port executable requires `CAP_NET_ADMIN` to communicate with the kernel firewall:

```bash
# After compilation
sudo setcap cap_net_admin=ep priv/port_nftables
```

This is done automatically during `mix compile` if you have sudo access.

## Usage

### Direct Usage

```elixir
# Start the port
{:ok, pid} = NFTablesEx.Port.start_link()

# Send a request to list tables
request = ~s({"nftables": [{"list": {"tables": {}}}]})
{:ok, response} = NFTablesEx.Port.commit(pid, request)

# Parse response
{:ok, data} = Jason.decode(response)

# Stop the port
NFTablesEx.Port.stop(pid)
```

### With NFTablesEx

Typically, you'll use NFTablesEx.Port indirectly through the NFTablesEx high-level API, which provides a clean, idiomatic Elixir interface:

```elixir
alias NFTablesEx.{Table, Chain, RuleBuilder}

# NFTablesEx automatically manages the port
{:ok, pid} = NFTablesEx.start_link()

# Create table and chain
Table.add(pid, %{name: "filter", family: :inet})
Chain.add(pid, %{
  table: "filter",
  name: "input",
  family: :inet,
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :accept
})

# Build and commit firewall rules using the rule builder
import RuleBuilder

# Block a specific IP address
rule =
  new()
  |> from_ipv4("192.168.1.100")
  |> drop()
  |> build("filter", "input")

Chain.add_rule(pid, rule)

# Allow established connections
rule =
  new()
  |> ct_state([:established, :related])
  |> accept()
  |> build("filter", "input")

Chain.add_rule(pid, rule)

# Rate-limit SSH connections
rule =
  new()
  |> to_port(22)
  |> protocol(:tcp)
  |> limit(rate: 10, per: :minute)
  |> accept()
  |> comment("Rate-limited SSH access")
  |> build("filter", "input")

Chain.add_rule(pid, rule)

# All of these rules are converted to JSON and sent through NFTablesEx.Port
```

The RuleBuilder provides a composable, type-safe way to build complex firewall rules. Behind the scenes, NFTablesEx.Port handles all the JSON communication with nftables.

## Port Executable Location

The port executable is located using this resolution order:

1. `PORT_NFTABLES_PATH` environment variable (if set and file exists)
2. `/usr/local/sbin/port_nftables` (system-wide installation)
3. `/usr/sbin/port_nftables` (system-wide installation)
4. `priv/port_nftables` (development or application-bundled)

For production deployments, either:
- Set `PORT_NFTABLES_PATH` to specify a custom location
- Install to `/usr/local/sbin/port_nftables`

## Building from Source

The Zig port executable is built automatically during `mix compile`:

```bash
mix deps.get
mix compile
```

The build process:
1. Compiles the Zig source code in `native/src/`
2. Creates the executable at `priv/port_nftables`
3. Attempts to set `CAP_NET_ADMIN` capability (requires sudo)

## Installing to System Location

For production deployments, install the port executable to a system location:

```bash
# Install to default location (/usr/local/sbin/port_nftables)
sudo mix nftables_ex_port.install

# Install to custom location
sudo mix nftables_ex_port.install /usr/sbin/port_nftables

# Install to custom directory (will create port_nftables in that directory)
sudo mix nftables_ex_port.install /opt/nftables/bin/
```

The install task:
- Copies the compiled executable to the specified location
- Sets executable permissions (755)
- Sets `CAP_NET_ADMIN` capability with `setcap`
- Provides clear instructions if any step fails

After installation to a standard location (`/usr/local/sbin` or `/usr/sbin`), NFTablesEx.Port will automatically find the executable. For custom locations, set the `PORT_NFTABLES_PATH` environment variable:

```bash
export PORT_NFTABLES_PATH=/opt/nftables/bin/port_nftables
```

## Testing

```bash
mix test
```

Note: Tests require:
- Root privileges or `CAP_NET_ADMIN` capability
- Linux system with nftables support

## Protocol

The port uses a simple length-prefixed packet protocol:

```
Request:  [4 bytes: length][N bytes: JSON string]
Response: [4 bytes: length][N bytes: JSON string]
```

Framing is handled automatically by Erlang's `{:packet, 4}` option.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [NFTablesEx](https://github.com/yourusername/nftables_ex) - High-level Elixir API for nftables
- [nftables](https://netfilter.org/projects/nftables/) - Linux kernel firewall

## Documentation

Full documentation is available at [HexDocs](https://hexdocs.pm/nftables_ex_port).

