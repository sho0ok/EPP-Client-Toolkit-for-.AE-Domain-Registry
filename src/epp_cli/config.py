"""
CLI Configuration

Handles configuration loading and management.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


# Default config locations
DEFAULT_CONFIG_PATHS = [
    Path("/etc/epp-client/client.yaml"),  # RPM installation path
    Path("/etc/epp-client/client.yml"),
    Path.home() / ".epp-client" / "client.yaml",
    Path.home() / ".epp" / "config.yaml",
    Path("epp_config.yaml"),
]


@dataclass
class ServerConfig:
    """EPP server configuration."""
    host: str
    port: int = 700
    timeout: int = 30
    verify_server: bool = True


@dataclass
class CertConfig:
    """Certificate configuration."""
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    ca_file: Optional[str] = None


@dataclass
class CredentialsConfig:
    """Credentials configuration."""
    client_id: Optional[str] = None
    password: Optional[str] = None


@dataclass
class PoolSettingsConfig:
    """Connection pool configuration for shell mode."""
    min_connections: int = 1
    max_connections: int = 3
    keepalive_interval: int = 600  # 40% of 25-min server timeout (ARI default)
    command_retries: int = 3


@dataclass
class CLIConfig:
    """Complete CLI configuration."""
    server: ServerConfig
    certs: CertConfig = field(default_factory=CertConfig)
    credentials: CredentialsConfig = field(default_factory=CredentialsConfig)
    pool: PoolSettingsConfig = field(default_factory=PoolSettingsConfig)
    profile: str = "default"

    @classmethod
    def from_dict(cls, data: dict, profile: str = "default") -> "CLIConfig":
        """
        Create config from dictionary.

        Args:
            data: Configuration dictionary
            profile: Profile name to use

        Returns:
            CLIConfig instance
        """
        # Get profile-specific config or use root
        if "profiles" in data and profile in data["profiles"]:
            profile_data = data["profiles"][profile]
        else:
            profile_data = data

        # Server config (required)
        server_data = profile_data.get("server", {})
        if not server_data.get("host"):
            raise ValueError("Server host is required in configuration")

        server = ServerConfig(
            host=server_data["host"],
            port=server_data.get("port", 700),
            timeout=server_data.get("timeout", 30),
            verify_server=server_data.get("verify_server", True),
        )

        # Certificate config
        certs_data = profile_data.get("certs", {})
        certs = CertConfig(
            cert_file=_expand_path(certs_data.get("cert_file")),
            key_file=_expand_path(certs_data.get("key_file")),
            ca_file=_expand_path(certs_data.get("ca_file")),
        )

        # Credentials config
        creds_data = profile_data.get("credentials", {})
        credentials = CredentialsConfig(
            client_id=creds_data.get("client_id"),
            password=creds_data.get("password"),
        )

        # Pool settings
        pool_data = profile_data.get("pool", {})
        pool = PoolSettingsConfig(
            min_connections=pool_data.get("min_connections", 1),
            max_connections=pool_data.get("max_connections", 3),
            keepalive_interval=pool_data.get("keepalive_interval", 600),
            command_retries=pool_data.get("command_retries", 3),
        )

        return cls(
            server=server,
            certs=certs,
            credentials=credentials,
            pool=pool,
            profile=profile,
        )

    @classmethod
    def from_file(cls, path: Path, profile: str = "default") -> "CLIConfig":
        """
        Load config from YAML file.

        Args:
            path: Path to config file
            profile: Profile name to use

        Returns:
            CLIConfig instance
        """
        with open(path) as f:
            data = yaml.safe_load(f)

        return cls.from_dict(data or {}, profile)

    @classmethod
    def find_and_load(cls, profile: str = "default") -> Optional["CLIConfig"]:
        """
        Find and load config from default locations.

        Args:
            profile: Profile name to use

        Returns:
            CLIConfig instance or None if not found
        """
        for path in DEFAULT_CONFIG_PATHS:
            if path.exists():
                return cls.from_file(path, profile)
        return None


def _expand_path(path: Optional[str]) -> Optional[str]:
    """Expand environment variables and ~ in path."""
    if path is None:
        return None
    return os.path.expandvars(os.path.expanduser(path))


def create_sample_config() -> str:
    """
    Generate sample configuration YAML.

    Returns:
        Sample config as YAML string
    """
    return """# EPP Client Configuration
# Default location: /etc/epp-client/client.yaml (RPM install)
# Alternative: ~/.epp-client/client.yaml (user install)

server:
  host: epp.aeda.ae
  port: 700
  timeout: 30
  verify_server: true

certs:
  cert_file: /etc/epp-client/tls/client.crt
  key_file: /etc/epp-client/tls/client.key
  ca_file: /etc/epp-client/tls/ca.crt

credentials:
  client_id: your-registrar-id
  password: your-password

# Connection pool settings for shell mode (optional)
pool:
  min_connections: 1
  max_connections: 3
  keepalive_interval: 600   # seconds (40% of 25-min server timeout)
  command_retries: 3

# Multiple profiles example (optional)
profiles:
  production:
    server:
      host: epp.aeda.ae
      port: 700
    certs:
      cert_file: /etc/epp-client/tls/client.crt
      key_file: /etc/epp-client/tls/client.key
      ca_file: /etc/epp-client/tls/ca.crt
    credentials:
      client_id: prod_registrar

  ote:
    server:
      host: epp-ote.aeda.ae
      port: 700
    certs:
      cert_file: /etc/epp-client/tls/ote-client.crt
      key_file: /etc/epp-client/tls/ote-client.key
      ca_file: /etc/epp-client/tls/ca.crt
    credentials:
      client_id: ote_registrar
"""
