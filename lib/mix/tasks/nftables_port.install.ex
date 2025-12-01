defmodule Mix.Tasks.NftablesPort.Install do
  @moduledoc """
  Install the nftables port executable to a system location.

  This task copies the compiled port executable to a system directory and
  sets the required CAP_NET_ADMIN capability. Requires sudo/root permissions.

  ## Usage

      # Install to default location (/usr/local/sbin/port_nftables)
      mix nftables_port.install

      # Install to custom location
      mix nftables_port.install /usr/sbin/port_nftables

      # Install to custom directory (filename will be port_nftables)
      mix nftables_port.install /opt/nftables/bin

  ## What it does

  1. Ensures the port executable is compiled
  2. Copies the executable to the specified location
  3. Sets executable permissions (755)
  4. Sets CAP_NET_ADMIN capability with setcap

  ## Requirements

  - Root/sudo access
  - `setcap` utility installed (part of libcap package)
  - Compiled port executable in priv/port_nftables

  ## Examples

      # System-wide installation
      sudo mix nftables_port.install

      # Custom path
      sudo mix nftables_port.install /opt/myapp/bin/port_nftables

      # Check if it worked
      getcap /usr/local/sbin/port_nftables
      # Should show: cap_net_admin=ep
  """

  use Mix.Task

  @shortdoc "Install the nftables port executable to a system location"

  @default_install_path "/usr/local/sbin/port_nftables"

  @impl Mix.Task
  def run(args) do
    # Ensure we're compiled
    Mix.Task.run("compile")

    install_path = parse_install_path(args)
    source_path = get_source_path()

    Mix.shell().info("Installing nftables port executable...")
    Mix.shell().info("  Source: #{source_path}")
    Mix.shell().info("  Target: #{install_path}")

    # Verify source exists
    unless File.exists?(source_path) do
      Mix.raise("""
      Port executable not found at #{source_path}
      Please run 'mix compile' first to build the executable.
      """)
    end

    # Ensure target directory exists
    target_dir = Path.dirname(install_path)
    ensure_directory(target_dir)

    # Copy the executable
    case File.cp(source_path, install_path) do
      :ok ->
        Mix.shell().info("✓ Copied executable to #{install_path}")

      {:error, reason} ->
        Mix.raise("""
        Failed to copy executable: #{inspect(reason)}
        Make sure you have write permissions to #{target_dir}
        Try running with sudo: sudo mix nftables_port.install
        """)
    end

    # Set executable permissions
    case System.cmd("chmod", ["755", install_path]) do
      {_, 0} ->
        Mix.shell().info("✓ Set executable permissions (755)")

      {output, _} ->
        Mix.shell().error("Warning: Failed to set permissions: #{output}")
    end

    # Set capabilities
    set_capabilities(install_path)

    Mix.shell().info("")
    Mix.shell().info("✓ Installation complete!")
    Mix.shell().info("")
    Mix.shell().info("To use this installation, set the environment variable:")
    Mix.shell().info("  export PORT_NFTABLES_PATH=#{install_path}")
    Mix.shell().info("")
    Mix.shell().info("Or, if installed to a standard location, NFTables.Port will find it automatically.")
  end

  # Parse command line arguments to determine install path
  defp parse_install_path([]), do: @default_install_path

  defp parse_install_path([path]) do
    cond do
      # If path ends with a directory separator or is an existing directory,
      # append the default filename
      String.ends_with?(path, "/") or File.dir?(path) ->
        Path.join(path, "port_nftables")

      # Otherwise use the path as-is (user specified full path including filename)
      true ->
        path
    end
  end

  defp parse_install_path(_) do
    Mix.raise("""
    Too many arguments. Usage:
      mix nftables_port.install [PATH]

    Examples:
      mix nftables_port.install
      mix nftables_port.install /usr/local/sbin/port_nftables
      mix nftables_port.install /opt/nftables/bin/
    """)
  end

  # Get the source path to the compiled executable
  defp get_source_path do
    # First try priv directory
    case :code.priv_dir(:nftables_port) do
      {:error, _} ->
        # Fall back to relative path (development)
        "priv/port_nftables"

      priv_dir when is_list(priv_dir) ->
        Path.join(to_string(priv_dir), "port_nftables")
    end
  end

  # Ensure the target directory exists
  defp ensure_directory(dir) do
    unless File.dir?(dir) do
      Mix.shell().info("Creating directory: #{dir}")

      case File.mkdir_p(dir) do
        :ok ->
          :ok

        {:error, reason} ->
          Mix.raise("""
          Failed to create directory #{dir}: #{inspect(reason)}
          Make sure you have appropriate permissions.
          Try running with sudo: sudo mix nftables_port.install
          """)
      end
    end
  end

  # Set CAP_NET_ADMIN capability on the executable
  defp set_capabilities(path) do
    # Check if setcap command exists
    case System.find_executable("setcap") do
      nil ->
        Mix.shell().error("""

        Warning: setcap command not found.
        Please install libcap package:
          - Debian/Ubuntu: sudo apt-get install libcap2-bin
          - RHEL/CentOS: sudo yum install libcap
          - Arch: sudo pacman -S libcap

        Then run manually:
          sudo setcap cap_net_admin=ep #{path}
        """)

        :error

      _setcap_path ->
        case System.cmd("setcap", ["cap_net_admin=ep", path], stderr_to_stdout: true) do
          {_, 0} ->
            Mix.shell().info("✓ Set CAP_NET_ADMIN capability")
            :ok

          {output, _exit_code} ->
            cond do
              String.contains?(output, "Operation not permitted") ->
                Mix.shell().error("""

                Warning: Permission denied setting capabilities.
                Please run with sudo:
                  sudo mix nftables_port.install

                Or set capabilities manually:
                  sudo setcap cap_net_admin=ep #{path}
                """)

              true ->
                Mix.shell().error("""

                Warning: Failed to set capabilities: #{String.trim(output)}

                Try running manually:
                  sudo setcap cap_net_admin=ep #{path}
                """)
            end

            :error
        end
    end
  end
end
