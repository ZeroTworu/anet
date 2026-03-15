# ANet VPN — Quick Start

Short guide: required files, running the server (Docker), and connecting from a client.

---

## 1. What you need

### On the server (Linux)

**Minimum files in one folder (e.g. `~/anet`):**

| File | Purpose |
|------|--------|
| `install.sh` | One-command setup: checks deps, builds image, generates config, starts container |
| `generate-config.sh` | Generates `server.toml` + keys (run by install or manually) |
| `generate-client-config.sh` | Builds ready-to-use `client.toml` from keys |
| `diagnose.sh` | Server health check |
| `Dockerfile` | Builds ANet server image |
| `docker-compose.yml` | Runs the server container |
| `openssl-server.cnf` | Used for QUIC certificate (SAN: alco) |
| `client-windows/client.toml` | Template for client config (will be overwritten by generate-client-config.sh) |

**Optional:** `anet/` — ANet source code (only needed if using `--build-from-source` flag). Default mode downloads prebuilt binaries from GitHub releases.

**Optional (tests):** `test-client-keys.sh`, `test-keys-from-keys-file.sh` — validate keys on Linux.

### On the client (Windows / Linux)

- ANet client binary (e.g. `anet-client.exe` or GUI, or `anet-client-cli` on Linux)
- `client.toml` — generated on the server and copied to the client (same folder as the executable)
- On Windows: `wintun.dll` in the same folder as the client

---

## 2. Server: install and run

### 🚀 Quick Mode (Prebuilt Binaries — Recommended)

**Default mode**: Downloads prebuilt binaries from GitHub releases. **No Rust compilation, no anet/ source needed!**

**SO lazy loader**: download and this script launch everything!

```bash
curl -sSL https://github.com/AlphaO612/easy_anet/releases/download/v1.0/i-am-so-lazy.sh | sudo bash
```

**One-time setup (on a Linux server):**

```bash
# Fix line endings if you copied files from Windows
sed -i 's/\r$//' install.sh generate-config.sh generate-client-config.sh diagnose.sh

chmod +x install.sh generate-config.sh generate-client-config.sh diagnose.sh

# Quick install: download prebuilt binaries, generate config, start (2-3 min)
sudo ./install.sh
```

This will:

- Check Docker, Docker Compose, TUN, ip_forward
- **Download prebuilt binaries** from GitHub releases (fast!)
- Build lightweight Docker image (~2-3 minutes)
- Generate `server/server.toml` and `server/client-keys.txt` (if not already valid)
- Start the container (host network, port 8443/UDP)

### 🔨 Build from Source (Alternative)

If you want to compile from Rust source code instead:

```bash
# Full install: clone anet (if needed), compile from source (10-15 min)
sudo ./install.sh --build-from-source
```

This will:

- Clone `anet/` from GitHub if missing
- Compile Rust code (slower, requires more resources)
- Generate config and start server

**Manual steps (if you prefer):**

```bash
# With custom options
./install.sh --clients 3 --bind 51820              # 3 clients, port 51820
./install.sh --build-from-source --external-if eth0  # Build from source, specify interface

# Or generate config separately
./generate-config.sh --clients 2              # 2 client key pairs
./generate-client-config.sh --server-address YOUR_SERVER_IP:8443
docker compose up -d                          # Uses prebuilt binaries by default
# docker compose -f docker-compose.build.yml up -d  # Or force build from source
```

**Available flags for install.sh:**

| Flag | Description | Default |
|------|-------------|---------|
| `--build-from-source` | Compile from Rust source instead of downloading binaries | Disabled (uses prebuilt) |
| `--clients N` | Number of client keys to generate | 1 |
| `--external-if IFACE` | Network interface for NAT (e.g., eth0, ens3) | Auto-detect |
| `--bind PORT` | UDP port to bind | 8443 |

**Useful commands:**

| Command | Description |
|--------|-------------|
| `docker compose logs -f anet-server` | View server logs |
| `docker compose restart anet-server` | Restart server |
| `docker compose down` | Stop server |
| `./diagnose.sh` | Run diagnostics |

---

## 3. Client: get config and connect

### 3.1. Generate client.toml on the server

On the server (after install / generate-config):

```bash
# Replace with your server’s public IP or hostname
./generate-client-config.sh --server-address 194.41.113.15:8443
```

This updates `client-windows/client.toml` with:

- `address` = server IP:port
- `private_key` and `server_pub_key` from `server/client-keys.txt`

Optional checks:

```bash
./test-keys-from-keys-file.sh                 # Validate server/client-keys.txt
./test-client-keys.sh client-windows/client.toml  # Validate generated client.toml
```

### 3.2. Copy config to the client

Copy the generated `client.toml` to the machine where the ANet client runs:

- **Windows:** same folder as `anet-client.exe` (or GUI exe) and `wintun.dll`
- **Linux:** same folder as the client binary, or pass config path as per client docs

Example (from your PC, replace `user` and `server`):

```bash
scp user@server:~/anet/client-windows/client.toml ./
# Then copy client.toml into the folder with anet-client.exe
```

Or copy the whole `client-windows/` folder (with exe, wintun.dll, client.toml) to the client.

### 3.3. Run the client

- **Windows GUI:** run `anet-gui.exe` (or `anet-client.exe`). It loads `client.toml` from the same folder.
- **Windows CLI:** run `anet-client.exe` from the folder that contains `client.toml`.
- **Linux:** run the CLI client from the directory with `client.toml` (or use its config option).

After connecting you should see something like “Authenticated”, “VPN Tunnel UP”, and your traffic will go through the server (check e.g. https://ifconfig.me — it should show the server’s IP).

---

## 4. Summary

| Step | Where | Command / action |
|------|--------|-------------------|
| 1. Install server | Linux server | `sudo ./install.sh` |
| 2. Generate client config | Linux server | `./generate-client-config.sh --server-address IP:8443` |
| 3. Copy client.toml | Server → client PC | `scp` or copy `client-windows/` |
| 4. Start client | Windows/Linux client | Run ANet client in the folder with `client.toml` |

**Port:** 8443/UDP must be open on the server (firewall/security group).
