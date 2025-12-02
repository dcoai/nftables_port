defmodule NFTables.Port.MixProject do
  use Mix.Project

  @version "0.4.1"
  @source_url "https://github.com/dcoai/nftables_port"

  def project do
    [
      app: :nftables_port,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: Mix.compilers() ++ [:zig],
      aliases: aliases(),

      # Test configuration
      test_pattern: "*_test.exs",
      test_coverage: [tool: ExCoveralls],

      # Hex package configuration
      description: description(),
      package: package(),

      # Docs
      name: "NFTables.Port",
      source_url: @source_url,
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:usage_rules, "~> 0.1.25", only: :dev},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end

  defp description do
    """
    NFTables.Port is an ELixir module that bridges Elixir and the
    Linux kernel's nftables firewall via an Elixir port.
    """
  end

  defp package do
    [
      name: "nftables_port",
      files: ~w(lib priv native/build.zig native/src .formatter.exs mix.exs README.md LICENSE),
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url
      },
      maintainers: ["Doug ClymerOlson"],
      source_url: @source_url
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: [
        "README.md",
        "LICENSE",
        "dev_docs/architecture.md",
        "dev_docs/capabilities.md",
        "dev_docs/security.md"
      ],
      groups_for_extras: [
        "Documentation": ["README.md", "LICENSE"],
        "Development": [
          "dev_docs/architecture.md",
          "dev_docs/capabilities.md",
          "dev_docs/security.md"
        ]
      ]
    ]
  end

  defp aliases do
    [
      "compile.zig": &run_zig_compile/1,
      clean: ["clean", &run_zig_clean/1]
    ]
  end

  defp run_zig_compile(_args) do
    Mix.Tasks.Compile.Zig.run([])
  end

  defp run_zig_clean(_args) do
    Mix.Tasks.Compile.Zig.clean()
  end
end
