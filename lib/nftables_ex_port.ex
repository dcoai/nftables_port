defmodule NFTables.Port do
  @moduledoc """
  GenServer managing the nftables port process with JSON communication.

  This module provides the low-level interface to nftables via a native Zig port
  executable. All communication uses JSON format through the official libnftables
  library, providing a simple, performant, and safe interface to the kernel firewall.

  ## Architecture

  ```
  NFTables.Port (GenServer)
         ↓
  Erlang Port (Zig executable)
         ↓
  libnftables (C library)
         ↓
  Linux Kernel (nftables)
  ```

  ## Communication Flow

  ```
  Request:  Elixir JSON → [4-byte length][JSON bytes] → Zig → libnftables → kernel
  Response: kernel → libnftables → Zig → [4-byte length][JSON bytes] → Elixir JSON
  ```

  ## Protocol

  The port uses 4-byte big-endian length-prefixed packets for framing:

  ```
  [4 bytes: packet length][N bytes: JSON string]
  ```

  This framing is handled automatically by Erlang's `{:packet, 4}` option.

  ## Port Binary Location

  The native port executable is located using the following resolution order:

  1. **PORT_NFTABLES_PATH** environment variable (if set and file exists)
  2. **/usr/local/sbin/port_nftables** (system-wide installation)
  3. **/usr/sbin/port_nftables** (system-wide installation)
  4. **priv/port_nftables** (development or application-bundled)

  For production deployments, set the `PORT_NFTABLES_PATH` environment variable
  to specify a custom location, or install to `/usr/local/sbin/port_nftables`.

  ## Capabilities

  The port executable requires `CAP_NET_ADMIN` capability to communicate with
  the kernel firewall. Set it with:

      sudo setcap cap_net_admin=ep /path/to/port_nftables

  ## Usage Example

      # Start the port process
      {:ok, pid} = NFTables.Port.start_link()

      # Send a request to list tables
      request = ~s({"nftables": [{"list": {"tables": {}}}]})
      {:ok, response} = NFTables.Port.commit(pid, request)

      # Parse the response
      {:ok, data} = Jason.decode(response)

  ## Direct Usage vs High-Level APIs

  This module is typically used indirectly through NFTables high-level APIs
  (Table, Chain, Rule, Set, etc.) which handle JSON construction and parsing.
  Direct usage is appropriate for:

  - Custom nftables operations not covered by high-level APIs
  - Performance-critical code paths
  - Advanced nftables features
  - Testing and debugging
  """

  use GenServer
  require Logger

  @default_timeout 5_000

  defmodule State do
    @moduledoc false

    @typedoc """
    Internal GenServer state.

    - `port` - Erlang port handle to the native executable
    - `pending` - GenServer.from() tuple for the caller waiting for response
    - `check_capabilities` - Whether to check CAP_NET_ADMIN on startup
    """
    @type t :: %__MODULE__{
            port: port() | nil,
            pending: GenServer.from() | nil,
            check_capabilities: boolean()
          }

    defstruct [:port, :pending, check_capabilities: true]
  end

  ## Client API

  @doc """
  Start the nftables port GenServer.

  Spawns the native Zig port executable and establishes JSON communication.
  The port process will remain running until explicitly stopped or until it
  crashes (in which case this GenServer will also terminate).

  ## Options

  - `:check_capabilities` - Check for CAP_NET_ADMIN capability on startup (default: true)
  - `:name` - Register the GenServer with a name (optional)

  ## Returns

  - `{:ok, pid}` - Successfully started port GenServer
  - `{:error, reason}` - Failed to start

  ## Examples

      # Start with default options
      {:ok, pid} = NFTables.Port.start_link()

      # Start with named registration
      {:ok, pid} = NFTables.Port.start_link(name: MyApp.NFTablesPort)

      # Skip capability check (not recommended for production)
      {:ok, pid} = NFTables.Port.start_link(check_capabilities: false)
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Commit a request to nftables and wait for response.

  Sends a JSON-formatted nftables request to the port process, which forwards it
  to the native port executable that communicates with libnftables. The function
  blocks until a response is received or the timeout expires.

  ## Parameters

  - `pid` - The port GenServer PID
  - `request` - JSON string containing nftables commands
  - `timeout` - Timeout in milliseconds (default: 5000)

  ## Returns

  - `{:ok, json_string}` - Success, returns JSON string response from nftables
  - `{:error, reason}` - Error occurred during request processing

  ## Examples

      # List all tables
      request = ~s({"nftables": [{"list": {"tables": {}}}]})
      {:ok, response} = NFTables.Port.commit(pid, request)

      # Add a table
      request = ~s({"nftables": [{"add": {"table": {"family": "inet", "name": "filter"}}}]})
      {:ok, response} = NFTables.Port.commit(pid, request)

      # With custom timeout
      {:ok, response} = NFTablesEx.Port.commit(pid, request, 10_000)
  """
  def commit(pid, request, timeout \\ @default_timeout) when is_binary(request) do
    GenServer.call(pid, {:request, request}, timeout)
  end

  @doc """
  Stop the port GenServer.

  Gracefully shuts down the port process and closes the connection to the
  native port executable. Any pending requests will fail.

  ## Parameters

  - `pid` - The port GenServer PID

  ## Returns

  - `:ok`

  ## Examples

      {:ok, pid} = NFTables.Port.start_link()
      # ... use the port ...
      :ok = NFTables.Port.stop(pid)
  """
  def stop(pid) do
    GenServer.stop(pid, :normal)
  end

  ## Server Callbacks

  @impl true
  def init(opts) do
    check_capabilities = Keyword.get(opts, :check_capabilities, true)

    state = %State{
      port: nil,
      pending: nil,
      check_capabilities: check_capabilities
    }

    {:ok, state, {:continue, :start_port}}
  end

  @impl true
  def handle_continue(:start_port, state) do
    port_path = get_port_path()

    # Open the native Zig port executable with packet framing
    # Options:
    #   :binary - Use binary mode for data
    #   :exit_status - Receive {:exit_status, status} if port crashes
    #   {:packet, 4} - Automatic 4-byte big-endian length prefixing for framing
    #   :use_stdio - Communicate via stdin/stdout
    port =
      Port.open({:spawn_executable, port_path}, [
        :binary,
        :exit_status,
        {:packet, 4},
        :use_stdio
      ])

    {:noreply, %{state | port: port}}
  end

  @impl true
  def handle_call({:request, request}, from, state) when is_binary(request) do
    # Send JSON request string to port (automatic 4-byte length prefix added by {:packet, 4})
    Port.command(state.port, request)

    # Store caller info to reply when response arrives
    # Note: We return :noreply here and reply later in handle_info
    {:noreply, %{state | pending: from}}
  end

  @impl true
  def handle_info({port, {:data, response}}, %{port: port, pending: from} = state) do
    # Received response from port (4-byte length prefix automatically stripped by {:packet, 4})
    # Reply to the waiting caller with the JSON response string
    GenServer.reply(from, {:ok, response})
    {:noreply, %{state | pending: nil}}
  end

  @impl true
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    Logger.error("NFTables.Port exited with status #{status}")
    {:stop, {:port_exit, status}, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warning("NFTables.Port received unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    if state.port do
      Port.close(state.port)
    end

    :ok
  end

  ## Private Functions

  # Determine the path to the native port executable.
  #
  # Resolution order:
  # 1. PORT_NFTABLES_PATH environment variable (if set and exists)
  # 2. Standard system paths (/usr/local/sbin, /usr/sbin)
  # 3. Application-specific paths (priv dir or native build dir)
  #
  # Returns the first existing path found, or falls back to application paths.
  defp get_port_path do
    case System.get_env("PORT_NFTABLES_PATH") do
      nil ->
        find_port_in_system()

      path when is_binary(path) ->
        if File.exists?(path) do
          path
        else
          find_port_in_system()
        end
    end
  end

  # Search for port executable in standard system directories.
  #
  # Checks common installation paths for system-wide installations.
  # Falls back to application-specific paths if not found.
  defp find_port_in_system do
    system_paths = [
      "/usr/local/sbin/port_nftables",
      "/usr/sbin/port_nftables"
    ]

    Enum.find(system_paths, &File.exists?/1) || fallback_port_path()
  end

  # Get the fallback path for the port executable.
  #
  # In development (when Mix is available):
  #   - First tries the application priv directory
  #   - Falls back to native build directory for local builds
  #
  # In production (release):
  #   - Uses the application priv directory from the release
  defp fallback_port_path do
    cond do
      Code.ensure_loaded?(Mix.Project) ->
        # Development environment
        priv_dir = :code.priv_dir(:nftables_port)

        case priv_dir do
          {:error, _} ->
            # Priv dir not available yet, use native build directory
            "native/zig-out/bin/port_nftables"

          dir when is_list(dir) ->
            # Priv dir available
            Path.join(to_string(dir), "port_nftables")
        end

      true ->
        # Production environment (release)
        Application.app_dir(:nftables_port, "priv/port_nftables")
    end
  end
end
