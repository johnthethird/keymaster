# 🔑 Keymaster

<div align="center">
  <em>Secure macOS Keychain helper – guarded by <strong>Touch ID</strong> <em>and</em> your login password</em>
</div>


<p align="center">
  <img alt="Swift" src="https://img.shields.io/badge/swift-5.9-orange?logo=swift" />
  <img alt="macOS" src="https://img.shields.io/badge/macOS-12%20%2B-blue?logo=apple" />
  <img alt="License MIT" src="https://img.shields.io/badge/License-MIT-green" />
</p>


Keymaster is a tiny CLI that lets you store, retrieve, and delete small secrets in your macOS Keychain from scripts – protected by Touch ID or your login password. The first time you access a secret you can Always Allow the binary; every subsequent call prompts for biometrics and automatically falls back to a password sheet when Touch ID is unavailable.

---

## ✨ Features
- 🔐 Stores secrets in the system Keychain (kSecClassGenericPassword)
- 👆 Biometric protection via Touch ID
- 🔑 Automatic fallback to macOS login password
- ⚡️ Single self-contained binary, no dependencies
- 📝 Friendly CLI (set, get, delete) with built-in help
- 🛠 Written in Swift – easy to audit & build

---

## 📦 Installation

### Clone or download this repo
```shell
git clone https://github.com/bmansvk/keymaster.git
cd keymaster
```
### Compile
```swiftc keymaster.swift -o keymaster```

### Put the executable somewhere on your $PATH
```mv keymaster ~/.local/bin```  

Tip: Compile with -O for release optimisation.

---

## 🚀 Usage

```shell
keymaster set <key> <secret>              Store or update <secret> for <key>
keymaster get <key> [options]             Print secret to stdout
keymaster delete <key>                    Remove secret from Keychain

Options:
-h, --help                                Show detailed help and exit
-d, --description <text>                  Custom description for biometric prompt (get only)
```

### Examples

#### Save a GitHub token
```keymaster set github_token "ghp_abc123"```

#### Read it back
```GITHUB_TOKEN=$(keymaster get github_token)```

When running `get`, keymaster will show which key is being read:
```
Reading key "github_token" from Keychain...
```

#### Use a custom biometric prompt
```keymaster get vpn_password --description "VPN wants to authenticate"```

This will show "VPN wants to authenticate" in the Touch ID/password prompt instead of the default message.

#### Remove when no longer needed
```keymaster delete github_token```

Inside a Bash script:
```shell
#!/usr/bin/env bash
set -euo pipefail

API_KEY=$(keymaster get my_service_api_key)
curl -H "Authorization: Bearer $API_KEY" https://api.example.com/v1/...
```

---

## 🔒 How it works
1.	Keymaster calls SecItemAdd / SecItemCopyMatching / SecItemDelete from the Security framework.
2.	Before each operation it triggers LAContext.evaluatePolicy(.deviceOwnerAuthentication).
3.	macOS shows a single sheet:
- Touch ID or
- Use Password… → falls back to your login password.
4.	Only on success does the CLI proceed; otherwise it exits with a non-zero status.

Because secrets never leave the Keychain and the binary is code-signed by you, this approach is safer than environment variables or plain files.

---

## 🙏 Credits
Forked from johnthethird/keymaster – thanks for the original idea and groundwork.

---

---

# Keymasterd

<div align="center">
  <em>HTTP daemon for secure macOS Keychain access – guarded by <strong>Touch ID</strong> <em>and</em> your login password</em>
</div>

Keymasterd is an HTTP server that exposes Keychain secrets over a local HTTP API. Each request triggers biometric/password authentication, making it suitable for automated tools that need secure secret access with user confirmation.

---

## Features
- HTTP API for Keychain access
- Touch ID / password authentication per request
- HTTP Basic Authentication for client verification
- Configurable via command-line arguments and environment variables
- Runs as a macOS launchd service
- Password passed via environment variable (not visible in process list)

---

## Installation

### Build
```shell
swiftc keymasterd.swift -o keymasterd
```

### Install
```shell
mv keymasterd /usr/local/bin/
```

---

## Usage

```shell
keymasterd [options]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --port <port>` | Port to listen on | 8787 |
| `-b, --bind <host>` | Host/IP to bind to | 127.0.0.1 |
| `-u, --username <user>` | HTTP Basic Auth username | (none) |
| `-d, --description <text>` | Custom biometric prompt text | "Keymasterd wants to access the Keychain" |
| `-h, --help` | Display help message | |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `KEYMASTERD_PASSWORD` | HTTP Basic Auth password (required with `-u`) |
| `KEYMASTERD_USERNAME` | HTTP Basic Auth username (alternative to `-u`) |
| `KEYMASTERD_PORT` | Port to listen on (alternative to `-p`) |
| `KEYMASTERD_BIND` | Host/IP to bind to (alternative to `-b`) |

Command-line arguments override environment variables.

---

## API Endpoints

### GET /key/<keyname>
Retrieve a secret from the Keychain. Triggers biometric/password authentication.

**Response:**
- `200 OK` - Secret value in plain text
- `401 Unauthorized` - Missing or invalid HTTP Basic Auth
- `403 Forbidden` - Biometric/password authentication failed
- `404 Not Found` - Key not found in Keychain

### GET /health
Health check endpoint. Returns `OK` if server is running.

---

## Examples

### Start server with HTTP Basic Auth
```shell
KEYMASTERD_PASSWORD=secret123 keymasterd --port 9000 --username admin
```

### Retrieve a secret with curl
```shell
curl -u admin:secret123 http://localhost:9000/key/github_token
```

### Use in a script
```shell
#!/usr/bin/env bash
API_KEY=$(curl -s -u admin:secret123 http://localhost:8787/key/my_api_key)
curl -H "Authorization: Bearer $API_KEY" https://api.example.com/v1/...
```

---

## Running as a macOS Service

### 1. Copy the plist template
```shell
cp com.keymaster.keymasterd.plist ~/Library/LaunchAgents/
```

### 2. Edit the plist
Update the following in `~/Library/LaunchAgents/com.keymaster.keymasterd.plist`:
- Set `KEYMASTERD_PASSWORD` to a secure password
- Adjust username and other options as needed

### 3. Load the service
```shell
launchctl load ~/Library/LaunchAgents/com.keymaster.keymasterd.plist
```

### 4. Check status
```shell
launchctl list | grep keymasterd
curl http://localhost:8787/health
```

### 5. View logs
```shell
tail -f /tmp/keymasterd.log
```

### 6. Unload the service
```shell
launchctl unload ~/Library/LaunchAgents/com.keymaster.keymasterd.plist
```

---

## Security Considerations

- **Localhost binding**: By default, keymasterd binds to `127.0.0.1`, restricting access to local processes only
- **HTTP Basic Auth**: Always configure authentication when exposing to any network
- **Password via env**: The HTTP auth password is passed via `KEYMASTERD_PASSWORD` environment variable, keeping it hidden from `ps` output
- **Per-request auth**: Each Keychain access triggers Touch ID or password prompt
- **HTTPS**: For production use over a network, consider placing keymasterd behind an HTTPS reverse proxy

---

## On-Demand Mode (inetd-style)

For systems where you don't want keymasterd running continuously, use the inetd-compatible version. Launchd listens on the socket and spawns keymasterd-inetd only when a request arrives.

### Build
```shell
swiftc keymasterd-inetd.swift -o keymasterd-inetd
mv keymasterd-inetd /usr/local/bin/
```

### Configuration

The inetd version uses environment variables only:

| Variable | Description |
|----------|-------------|
| `KEYMASTERD_USERNAME` | HTTP Basic Auth username |
| `KEYMASTERD_PASSWORD` | HTTP Basic Auth password |
| `KEYMASTERD_DESCRIPTION` | Custom biometric prompt text |

### Setup

1. Copy the plist:
```shell
cp com.keymaster.keymasterd-inetd.plist ~/Library/LaunchAgents/
```

2. Edit `~/Library/LaunchAgents/com.keymaster.keymasterd-inetd.plist`:
   - Set `KEYMASTERD_PASSWORD` to a secure password
   - Adjust username as needed

3. Load the service:
```shell
launchctl load ~/Library/LaunchAgents/com.keymaster.keymasterd-inetd.plist
```

### How it works

1. Launchd listens on port 8787
2. When a connection arrives, launchd spawns `keymasterd-inetd`
3. The HTTP request is passed via stdin, response via stdout
4. Process exits after handling the single request
5. No daemon runs between requests

### Comparison

| Feature | keymasterd | keymasterd-inetd |
|---------|------------|------------------|
| Running process | Always | On-demand only |
| Memory usage | Constant | Zero when idle |
| First request latency | Instant | ~100ms spawn time |
| Configuration | CLI args + env | Environment only |
| Plist | `com.keymaster.keymasterd.plist` | `com.keymaster.keymasterd-inetd.plist` |

---

📜 License

This project is licensed under the MIT License – see LICENSE for details.