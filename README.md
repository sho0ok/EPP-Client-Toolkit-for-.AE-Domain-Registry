# EPP Client Toolkit for .AE Domain Registry

A production-ready EPP client for .AE domain registrars. Provides CLI tool and Python library.

## Features

- **Core EPP**: Domain, Contact, Host operations (RFC 5731-5733)
- **Extensions**: AE/AR/AU eligibility, ENUM/E.164, IDN, Variants, Key-Value metadata
- **CLI Modes**:
  - **Normal Mode**: One command per execution (traditional CLI)
  - **Shell Mode**: Interactive REPL with persistent connections
- **Async Support**: Connection pooling for high-throughput applications

## Requirements

- RHEL 9+ (Rocky Linux 9, AlmaLinux 9)
- TLS certificates from registry
- Python 3.9 (included in RHEL 9)

## Installation

### Step 1: Download RPM

Download the latest RPM from [Releases](https://github.com/sho0ok/EPP-Client-Toolkit-for-.AE-Domain-Registry/releases).

### Step 2: Copy to server

```bash
scp epp-client-1.0.0-1.el9.x86_64.rpm user@your-server:/tmp/
```

### Step 3: Install (no internet required)

```bash
ssh user@your-server
yum install /tmp/epp-client-1.0.0-1.el9.x86_64.rpm
```

### Step 4: Add your certificates

Copy your certificates to `/etc/epp-client/tls/`:
```bash
cp client.crt /etc/epp-client/tls/
cp client.key /etc/epp-client/tls/
cp ca.crt /etc/epp-client/tls/
chmod 600 /etc/epp-client/tls/*.key
```

### Step 5: Configure

```bash
vi /etc/epp-client/client.yaml
```

Update:
```yaml
server:
  host: "epp.aeda.ae"
  port: 700

credentials:
  client_id: "your-registrar-id"
  password: "your-password"
```

### Step 6: Test

```bash
epp domain check example.ae
```

---

## CLI Usage Modes

The EPP client supports two modes of operation:

| Mode | Best For | Connection Behavior |
|------|----------|---------------------|
| **Normal Mode** | Single commands, scripts, cron jobs | Connect → Login → Command → Logout → Disconnect |
| **Shell Mode** | Interactive sessions, multiple commands | Connect → Login → Many Commands → Logout → Disconnect |

---

## Normal Mode (Traditional CLI)

Each command connects, logs in, executes, logs out, and disconnects. Simple and stateless.

### Domain Commands

```bash
# Check domain availability
epp domain check example.ae test.ae

# Get domain info
epp domain info example.ae

# Create domain
epp domain create newdomain.ae --registrant REG001 --admin ADM001 --tech TCH001

# Create domain with nameservers
epp domain create newdomain.ae --registrant REG001 --ns ns1.example.ae --ns ns2.example.ae

# Renew domain
epp domain renew example.ae --exp-date 2025-12-31 --period 1

# Delete domain
epp domain delete example.ae --confirm

# Update domain (add/remove nameservers, statuses)
epp domain update example.ae --add-ns ns3.example.ae --rem-ns ns1.example.ae

# Transfer domain
epp domain transfer example.ae request --auth-info "transferSecret123"
epp domain transfer example.ae approve
epp domain transfer example.ae reject
```

### Contact Commands

```bash
# Check contact availability
epp contact check CONT001 CONT002

# Get contact info
epp contact info CONT001

# Create contact
epp contact create CONT001 \
    --name "John Doe" \
    --email "john@example.ae" \
    --city "Dubai" \
    --country AE \
    --voice "+971.41234567"

# Update contact
epp contact update CONT001 --email "newemail@example.ae"

# Delete contact
epp contact delete CONT001 --confirm
```

### Host Commands

```bash
# Check host availability
epp host check ns1.example.ae ns2.example.ae

# Get host info
epp host info ns1.example.ae

# Create host with IP addresses
epp host create ns1.example.ae --ipv4 192.168.1.1 --ipv6 2001:db8::1

# Update host
epp host update ns1.example.ae --add-ipv4 192.168.1.2 --rem-ipv4 192.168.1.1

# Delete host
epp host delete ns1.example.ae --confirm
```

### Poll Commands

```bash
# Get next message from poll queue
epp poll request

# Acknowledge message
epp poll ack 12345
```

### Output Formats

```bash
# Table format (default)
epp domain info example.ae

# JSON format
epp domain info example.ae --format json

# XML format (raw EPP response)
epp domain info example.ae --format xml
```

---

## Shell Mode (Interactive REPL)

Shell mode maintains persistent connections with automatic keep-alive. Login once, run many commands.

### Starting Shell Mode

```bash
# Using config file
epp shell

# With specific config
epp -c /path/to/config.yaml shell

# With specific profile
epp --profile production shell
```

### Shell Session Example

```
$ epp shell
Password: ********
SUCCESS: Connected! Pool: 1 connection(s)
INFO: Keep-alive every 600s
INFO: Type 'help' for available commands, 'quit' to exit.

epp> domain check example.ae test.ae
Name        Available  Reason
----------  ---------  ------
example.ae  No         In use
test.ae     Yes

epp> domain info example.ae
Name          : example.ae
Status        : ok
Registrant    : REG-001
Created       : 2020-01-15
Expiry Date   : 2025-01-15
Nameservers   : ns1.example.ae, ns2.example.ae

epp> contact check CONT001
Id       Available
-------  ---------
CONT001  No

epp> host info ns1.example.ae
Name    : ns1.example.ae
Status  : ok
IPv4    : 192.168.1.1

epp> status
Pool size:           1
Available:           1
In use:              0
Min connections:     1
Max connections:     3
Keep-alive interval: 600s

epp> hello
Server Id  : EPP Server
Version    : 1.0
Lang       : en

epp> quit
INFO: All connections closed.
```

### Available Shell Commands

| Command | Description |
|---------|-------------|
| `domain check <name> [name ...]` | Check domain availability |
| `domain info <name>` | Get domain information |
| `domain create <name> --registrant <id> [--ns <ns>] [--period <n>]` | Create a domain |
| `domain delete <name>` | Delete a domain |
| `domain renew <name> --exp-date <date> [--period <n>]` | Renew a domain |
| `contact check <id> [id ...]` | Check contact availability |
| `contact info <id>` | Get contact information |
| `host check <name> [name ...]` | Check host availability |
| `host info <name>` | Get host information |
| `host create <name> [--ipv4 <ip>] [--ipv6 <ip>]` | Create a host |
| `poll request` | Get next poll message |
| `poll ack <msg_id>` | Acknowledge poll message |
| `hello` | Send hello (test connection) |
| `status` | Show pool statistics |
| `help` | Show available commands |
| `quit` / `exit` | Close connections and exit |

### How Shell Mode Works

```
┌─────────────────────────────────────────────────┐
│              Connection Pool                     │
├─────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐         │
│  │ Conn 1  │  │ Conn 2  │  │ Conn 3  │         │
│  │(logged  │  │(logged  │  │(logged  │         │
│  │  in)    │  │  in)    │  │  in)    │         │
│  └─────────┘  └─────────┘  └─────────┘         │
├─────────────────────────────────────────────────┤
│  Background Keep-alive Thread                   │
│  └─ Sends hello() every 600s to prevent timeout │
└─────────────────────────────────────────────────┘
```

**Benefits:**
- **Fast**: No login/logout overhead per command
- **Persistent**: Connections stay open until you quit
- **Reliable**: Auto keep-alive prevents server timeout (25 min)
- **Resilient**: Auto-reconnect and retry on connection failures

### Shell Mode vs Normal Mode

| Aspect | Normal Mode | Shell Mode |
|--------|-------------|------------|
| Connection | Per command | Persistent pool |
| Login | Every command | Once at start |
| Speed | ~2s overhead | Near-instant |
| Keep-alive | None | Every 600s |
| Best for | Scripts, cron | Interactive use |
| Exit | Automatic | Type `quit` |

---

## Configuration

### Configuration File

`/etc/epp-client/client.yaml`:
```yaml
server:
  host: "epp.aeda.ae"
  port: 700
  timeout: 30
  verify_server: true

tls:
  cert_file: /etc/epp-client/tls/client.crt
  key_file: /etc/epp-client/tls/client.key
  ca_file: /etc/epp-client/tls/ca.crt

credentials:
  client_id: "your-registrar-id"
  password: "your-password"

# Connection pool settings for shell mode
pool:
  min_connections: 1        # Minimum connections to maintain
  max_connections: 3        # Maximum connections in pool
  keepalive_interval: 600   # Keep-alive interval (seconds)
  command_retries: 3        # Retries on connection failure
```

### Pool Configuration Explained

| Setting | Default | Description |
|---------|---------|-------------|
| `min_connections` | 1 | Connections created at shell startup |
| `max_connections` | 3 | Maximum concurrent connections |
| `keepalive_interval` | 600 | Seconds between keep-alive pings (40% of 25-min server timeout) |
| `command_retries` | 3 | Retry attempts on connection failure |

### Multiple Profiles

```yaml
# Default profile
server:
  host: "epp.aeda.ae"

credentials:
  client_id: "prod-registrar"

# Named profiles
profiles:
  production:
    server:
      host: "epp.aeda.ae"
    credentials:
      client_id: "prod-registrar"

  ote:
    server:
      host: "epp-ote.aeda.ae"
    credentials:
      client_id: "ote-registrar"
```

Use with:
```bash
epp --profile ote domain check example.ae
epp --profile ote shell
```

### Command Line Options

Override config file settings:
```bash
epp --host epp.aeda.ae \
    --cert /path/to/client.crt \
    --key /path/to/client.key \
    --client-id your-registrar-id \
    --password your-password \
    domain check example.ae
```

### Environment Variables

```bash
export EPP_PASSWORD="your-password"
epp domain check example.ae
```

### Generate Sample Config

```bash
epp config init
# Creates ~/.epp-client/client.yaml with sample configuration

epp config init --path /etc/epp-client/client.yaml
# Creates config at specified path
```

---

## Python Library

### Basic Usage

```python
from epp_client import EPPClient

client = EPPClient(
    host="epp.aeda.ae",
    port=700,
    cert_file="/etc/epp-client/tls/client.crt",
    key_file="/etc/epp-client/tls/client.key",
    ca_file="/etc/epp-client/tls/ca.crt",
)

with client:
    client.login("registrar_id", "password")

    # Check domain
    result = client.domain_check(["example.ae"])
    print(f"Available: {result.results[0].available}")

    # Get domain info
    info = client.domain_info("example.ae")
    print(f"Registrant: {info.registrant}")

    client.logout()
```

### Using Synchronous Connection Pool

```python
from epp_client import SyncEPPConnectionPool, SyncPoolConfig

config = SyncPoolConfig(
    host="epp.aeda.ae",
    port=700,
    cert_file="/etc/epp-client/tls/client.crt",
    key_file="/etc/epp-client/tls/client.key",
    ca_file="/etc/epp-client/tls/ca.crt",
    client_id="registrar_id",
    password="password",
    min_connections=1,
    max_connections=3,
    keepalive_interval=600,
)

pool = SyncEPPConnectionPool(config)
pool.start()

try:
    # Acquire connection from pool (already logged in)
    with pool.acquire() as client:
        result = client.domain_check(["example.ae"])
        print(result.results)

    # Or use execute_with_retry for automatic retry
    result = pool.execute_with_retry(
        lambda c: c.domain_info("example.ae")
    )
    print(result.registrant)
finally:
    pool.stop()
```

### Async Client

```python
import asyncio
from epp_client import AsyncEPPClient

async def main():
    client = AsyncEPPClient(
        host="epp.aeda.ae",
        port=700,
        cert_file="/etc/epp-client/tls/client.crt",
        key_file="/etc/epp-client/tls/client.key",
    )

    async with client:
        await client.login("registrar_id", "password")
        result = await client.domain_check(["example.ae"])
        print(result.results)
        await client.logout()

asyncio.run(main())
```

---

## Documentation

See [docs/](docs/) for detailed documentation on:
- EPP Extensions (AE, AR, AU, DNSSEC, IDN, ENUM)
- Error handling
- Advanced configuration

## License

MIT License
