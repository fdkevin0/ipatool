<p align="center">
  <a href="https://GitHub.com/majd/ipatool/releases/"><img src="https://img.shields.io/github/release/majd/ipatool.svg?label=Release" alt="Release"></a>
  <a href="https://github.com/majd/ipatool/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License"></a>
  <a href="https://github.com/sponsors/majd"><img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-pink.svg" alt="Sponsor"></a>
</p>

<p align="center">
  <code>ipatool</code> is a command line tool that allows you to search for iOS, iPadOS, tvOS, watchOS, visionOS, and macOS apps on the <a href="https://apps.apple.com">App Store</a>, and download <code>.ipa</code> or macOS <code>.pkg</code> app packages.
</p>

<p align="center">
  <img src="./resources/demo.gif" alt="Demo">
</p>

## Requirements

- A supported operating system (macOS, Linux, Windows or iOS).
- An Apple Account already configured to use the App Store.

## Installation

### Linux and Windows

You can grab the latest version of `ipatool` from [GitHub releases](https://github.com/majd/ipatool/releases).

### macOS

You can install `ipatool` using [Homebrew](https://brew.sh).

```shell
$ brew install ipatool
```

## Usage

To get started, run the following command.

```text
$ ipatool --help
A cli tool for interacting with Apple's ipa files

Usage:
  ipatool [command]

Available Commands:
  auth                 Authenticate with the App Store
  completion           Generate the autocompletion script for the specified shell
  download             Download iOS, iPadOS, tvOS, watchOS, visionOS, and macOS app packages from the App Store
  get-version-metadata Retrieves the metadata for a specific version of an app
  help                 Help about any command
  list-purchases       List apps owned by the authenticated App Store account
  list-versions        List the available versions of an App Store app
  mcp                  Serve App Store tools over MCP using stdio
  purchase             Obtain a license for the app from the App Store
  search               Search for iOS, iPadOS, tvOS, watchOS, visionOS, and macOS apps available on the App Store

Flags:
      --format format                sets output format for command; can be 'text', 'json' (default text)
  -h, --help                         help for ipatool
      --keychain-passphrase string   passphrase for unlocking keychain
      --non-interactive              run in non-interactive session
      --verbose                      enables verbose logs
  -v, --version                      version for ipatool

Use "ipatool [command] --help" for more information about a command.
```

**Note:** the tool runs in interactive mode by default. Use the `--non-interactive` flag
if running in an automated environment.

### Authentication

`ipatool auth login` supports password authentication with a six-digit verification
code when required. Experimental physical security-key login requires macOS and
libfido2, and uses the built-in local Anisette service by default (with an
optional `--anisette-url` override):

```shell
brew install libfido2
ipatool auth login --security-key --email you@example.com
```

Enter your password at the hidden prompt, then insert and touch one enrolled USB
key. Enter its local PIN if requested; Ctrl-C cancels. The password and PET are
not saved. Use the same build for subsequent commands; expired sessions require
another interactive security-key login, including when using MCP.

See [setup, protocol and verification limits](docs/apple-security-keys.md).

### MCP tools

Run `ipatool auth login` in a terminal, then configure your MCP client to launch the stdio server:

```json
{
  "mcpServers": {
    "ipatool": {
      "command": "ipatool",
      "args": ["mcp"]
    }
  }
}
```

## Compiling

The tool can be compiled using the Go toolchain.

```shell
$ go build -o ipatool
```

Unit tests can be executed with the following commands.

```shell
$ go generate ./...
$ go test -v ./...
```

## License

ipatool is released under the [MIT license](https://github.com/majd/ipatool/blob/main/LICENSE).
