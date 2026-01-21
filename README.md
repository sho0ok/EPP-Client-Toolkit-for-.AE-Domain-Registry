# EPP Client Toolkit for .AE Domain Registry

A production-ready EPP client for .AE domain registrars. Provides CLI tool and Python library.

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

## CLI Usage

```bash
# Check domain availability
epp domain check example.ae test.ae

# Get domain info
epp domain info example.ae

# Create domain
epp domain create newdomain.ae --registrant REG001 --admin ADM001 --tech TCH001

# Renew domain
epp domain renew example.ae --years 1

# Check contact
epp contact check CONT001

# Create contact
epp contact create CONT001 --name "John Doe" --email "john@example.ae"

# Check host
epp host check ns1.example.ae

# Create host
epp host create ns1.example.ae --ip 192.168.1.1
```

## Python Library

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

    client.logout()
```

## Configuration File

`/etc/epp-client/client.yaml`:
```yaml
server:
  host: "epp.aeda.ae"
  port: 700

tls:
  cert_file: /etc/epp-client/tls/client.crt
  key_file: /etc/epp-client/tls/client.key
  ca_file: /etc/epp-client/tls/ca.crt
  verify: true

credentials:
  client_id: "your-registrar-id"
  password: "your-password"

timeout:
  connect: 30
  read: 60
```

## Documentation

See [docs/](docs/) for detailed documentation.

## License

MIT License
