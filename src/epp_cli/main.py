"""
EPP CLI Main Entry Point

Command-line interface for EPP client operations.
"""

import getpass
import logging
import sys
from pathlib import Path
from typing import Optional

import click

from epp_client import EPPClient
from epp_client.exceptions import (
    EPPAuthenticationError,
    EPPCommandError,
    EPPConnectionError,
    EPPError,
    EPPObjectExists,
    EPPObjectNotFound,
)
from epp_client.models import AEEligibility, StatusValue
from epp_cli.config import CLIConfig, create_sample_config
from epp_cli.output import OutputFormatter, print_error, print_info, print_success


# Global state for the CLI session
class CLIState:
    client: Optional[EPPClient] = None
    config: Optional[CLIConfig] = None
    formatter: Optional[OutputFormatter] = None


state = CLIState()


# =============================================================================
# Main CLI Group
# =============================================================================

@click.group()
@click.option("--config", "-c", type=click.Path(exists=True), help="Config file path")
@click.option("--profile", "-p", default="default", help="Config profile to use")
@click.option("--host", "-h", help="EPP server hostname")
@click.option("--port", type=int, default=700, help="EPP server port")
@click.option("--cert", type=click.Path(exists=True), help="Client certificate file")
@click.option("--key", type=click.Path(exists=True), help="Client private key file")
@click.option("--ca", type=click.Path(exists=True), help="CA certificate file")
@click.option("--client-id", "-u", help="Client/registrar ID")
@click.option("--password", "-P", help="Password (or use EPP_PASSWORD env)")
@click.option("--timeout", type=int, default=30, help="Connection timeout")
@click.option("--no-verify", is_flag=True, help="Disable server certificate verification")
@click.option("--format", "-f", type=click.Choice(["table", "json", "xml"]), default="table", help="Output format")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.version_option(version="1.0.0")
@click.pass_context
def cli(ctx, config, profile, host, port, cert, key, ca, client_id, password, timeout, no_verify, format, quiet, debug):
    """
    EPP Client CLI - Domain Registry Operations

    Connect to an EPP server and manage domains, contacts, and hosts.

    \b
    Configuration:
      Use a config file at ~/.epp/config.yaml or specify options on command line.
      Run 'epp config init' to create a sample config file.

    \b
    Examples:
      epp --host epp.registry.ae --cert client.crt --key client.key domain check example.ae
      epp -c config.yaml domain info example.ae
      epp --profile production domain create example.ae --registrant contact123
    """
    # Setup logging
    if debug:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    # Setup formatter
    state.formatter = OutputFormatter(format=format, quiet=quiet)

    # Load config
    loaded_config = None
    if config:
        loaded_config = CLIConfig.from_file(Path(config), profile)
    else:
        loaded_config = CLIConfig.find_and_load(profile)

    # Build final config from loaded + CLI options
    if loaded_config:
        # CLI options override config file
        final_host = host or loaded_config.server.host
        final_port = port if port != 700 else loaded_config.server.port
        final_cert = cert or loaded_config.certs.cert_file
        final_key = key or loaded_config.certs.key_file
        final_ca = ca or loaded_config.certs.ca_file
        final_client_id = client_id or loaded_config.credentials.client_id
        final_password = password or loaded_config.credentials.password
        final_timeout = timeout if timeout != 30 else loaded_config.server.timeout
        final_verify = not no_verify and loaded_config.server.verify_server
    else:
        final_host = host
        final_port = port
        final_cert = cert
        final_key = key
        final_ca = ca
        final_client_id = client_id
        final_password = password
        final_timeout = timeout
        final_verify = not no_verify

    # Check for password in environment
    if not final_password:
        import os
        final_password = os.environ.get("EPP_PASSWORD")

    # Store in context for subcommands
    ctx.ensure_object(dict)
    ctx.obj["host"] = final_host
    ctx.obj["port"] = final_port
    ctx.obj["cert"] = final_cert
    ctx.obj["key"] = final_key
    ctx.obj["ca"] = final_ca
    ctx.obj["client_id"] = final_client_id
    ctx.obj["password"] = final_password
    ctx.obj["timeout"] = final_timeout
    ctx.obj["verify"] = final_verify


def get_client(ctx) -> EPPClient:
    """
    Get or create EPP client.

    Args:
        ctx: Click context

    Returns:
        Connected and logged-in EPP client
    """
    host = ctx.obj.get("host")
    if not host:
        print_error("No server host specified. Use --host or config file.")
        sys.exit(1)

    client_id = ctx.obj.get("client_id")
    if not client_id:
        print_error("No client ID specified. Use --client-id or config file.")
        sys.exit(1)

    password = ctx.obj.get("password")
    if not password:
        password = getpass.getpass("Password: ")

    try:
        client = EPPClient(
            host=host,
            port=ctx.obj.get("port", 700),
            cert_file=ctx.obj.get("cert"),
            key_file=ctx.obj.get("key"),
            ca_file=ctx.obj.get("ca"),
            timeout=ctx.obj.get("timeout", 30),
            verify_server=ctx.obj.get("verify", True),
        )

        client.connect()
        client.login(client_id, password)

        return client

    except EPPConnectionError as e:
        print_error(f"Connection failed: {e}")
        sys.exit(1)
    except EPPAuthenticationError as e:
        print_error(f"Authentication failed: {e}")
        sys.exit(1)


# =============================================================================
# Config Commands
# =============================================================================

@cli.group()
def config():
    """Configuration management commands."""
    pass


@config.command("init")
@click.option("--path", "-p", type=click.Path(), default="~/.epp/config.yaml", help="Config file path")
def config_init(path):
    """Create sample configuration file."""
    path = Path(path).expanduser()

    # Create parent directory
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        if not click.confirm(f"{path} already exists. Overwrite?"):
            return

    sample = create_sample_config()
    path.write_text(sample)

    print_success(f"Created config file: {path}")
    print_info("Edit the file to configure your EPP connection settings.")


@config.command("show")
@click.pass_context
def config_show(ctx):
    """Show current configuration."""
    info = {
        "Host": ctx.obj.get("host") or "(not set)",
        "Port": ctx.obj.get("port"),
        "Client ID": ctx.obj.get("client_id") or "(not set)",
        "Certificate": ctx.obj.get("cert") or "(not set)",
        "Key": ctx.obj.get("key") or "(not set)",
        "CA": ctx.obj.get("ca") or "(not set)",
        "Timeout": ctx.obj.get("timeout"),
        "Verify Server": ctx.obj.get("verify"),
    }
    state.formatter.output(info)


# =============================================================================
# Session Commands
# =============================================================================

@cli.command()
@click.pass_context
def hello(ctx):
    """Send hello command and show server greeting."""
    host = ctx.obj.get("host")
    if not host:
        print_error("No server host specified. Use --host or config file.")
        sys.exit(1)

    try:
        client = EPPClient(
            host=host,
            port=ctx.obj.get("port", 700),
            cert_file=ctx.obj.get("cert"),
            key_file=ctx.obj.get("key"),
            ca_file=ctx.obj.get("ca"),
            timeout=ctx.obj.get("timeout", 30),
            verify_server=ctx.obj.get("verify", True),
        )

        greeting = client.connect()
        state.formatter.output(greeting)
        client.disconnect()

    except EPPConnectionError as e:
        print_error(f"Connection failed: {e}")
        sys.exit(1)


# =============================================================================
# Domain Commands
# =============================================================================

@cli.group()
def domain():
    """Domain management commands."""
    pass


@domain.command("check")
@click.argument("names", nargs=-1, required=True)
@click.pass_context
def domain_check(ctx, names):
    """
    Check domain availability.

    NAMES: One or more domain names to check.
    """
    client = get_client(ctx)
    try:
        result = client.domain_check(list(names))
        state.formatter.output(result.results)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@domain.command("info")
@click.argument("name")
@click.option("--auth-info", "-a", help="Auth info for transfer query")
@click.pass_context
def domain_info(ctx, name, auth_info):
    """
    Get domain information.

    NAME: Domain name to query.
    """
    client = get_client(ctx)
    try:
        result = client.domain_info(name, auth_info=auth_info)
        state.formatter.output(result)
    except EPPObjectNotFound:
        print_error(f"Domain not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@domain.command("create")
@click.argument("name")
@click.option("--registrant", "-r", required=True, help="Registrant contact ID")
@click.option("--admin", "-a", help="Admin contact ID")
@click.option("--tech", "-t", help="Tech contact ID")
@click.option("--billing", "-b", help="Billing contact ID")
@click.option("--ns", "-n", multiple=True, help="Nameserver (can specify multiple)")
@click.option("--period", "-p", type=int, default=1, help="Registration period")
@click.option("--period-unit", type=click.Choice(["y", "m"]), default="y", help="Period unit (y=year, m=month)")
@click.option("--auth-info", help="Auth info (auto-generated if not provided)")
# AE Eligibility extension options for restricted zones (.co.ae, .gov.ae, etc.)
@click.option("--eligibility-type", help="Eligibility type (e.g., TradeLicense, Trademark)")
@click.option("--eligibility-name", help="Eligibility name (company/organization name)")
@click.option("--eligibility-id", help="Eligibility ID (license/trademark number)")
@click.option("--eligibility-id-type", help="Eligibility ID type (e.g., TradeLicense, Trademark)")
@click.option("--policy-reason", type=int, help="Policy reason (1-3)")
@click.option("--registrant-id", help="Registrant ID (e.g., Emirates ID)")
@click.option("--registrant-id-type", help="Registrant ID type (e.g., EmiratesID, Passport)")
@click.option("--registrant-name", help="Registrant name")
@click.pass_context
def domain_create(ctx, name, registrant, admin, tech, billing, ns, period, period_unit, auth_info,
                  eligibility_type, eligibility_name, eligibility_id, eligibility_id_type,
                  policy_reason, registrant_id, registrant_id_type, registrant_name):
    """
    Create a new domain.

    NAME: Domain name to create.

    For restricted zones (.co.ae, .gov.ae, .ac.ae, etc.), eligibility
    extension data may be required:

    \b
    Examples:

    \b
    # Standard .ae domain
    epp domain create example.ae --registrant contact123

    \b
    # Restricted .co.ae domain with eligibility
    epp domain create example.co.ae --registrant contact123 \\
        --eligibility-type TradeLicense \\
        --eligibility-name "Example Company LLC" \\
        --eligibility-id "123456" \\
        --eligibility-id-type TradeLicense
    """
    # Build AE eligibility extension if any eligibility options provided
    ae_eligibility = None
    if eligibility_type or eligibility_name:
        ae_eligibility = AEEligibility(
            eligibility_type=eligibility_type or "",
            eligibility_name=eligibility_name or "",
            eligibility_id=eligibility_id,
            eligibility_id_type=eligibility_id_type,
            policy_reason=policy_reason,
            registrant_id=registrant_id,
            registrant_id_type=registrant_id_type,
            registrant_name=registrant_name,
        )

    client = get_client(ctx)
    try:
        result = client.domain_create(
            name=name,
            registrant=registrant,
            admin=admin,
            tech=tech,
            billing=billing,
            nameservers=list(ns) if ns else None,
            period=period,
            period_unit=period_unit,
            auth_info=auth_info,
            ae_eligibility=ae_eligibility,
        )
        state.formatter.output(result)
        state.formatter.success(f"Domain created: {name}")
    except EPPObjectExists:
        print_error(f"Domain already exists: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@domain.command("delete")
@click.argument("name")
@click.option("--confirm", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def domain_delete(ctx, name, confirm):
    """
    Delete a domain.

    NAME: Domain name to delete.
    """
    if not confirm:
        if not click.confirm(f"Are you sure you want to delete {name}?"):
            return

    client = get_client(ctx)
    try:
        client.domain_delete(name)
        state.formatter.success(f"Domain deleted: {name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@domain.command("renew")
@click.argument("name")
@click.option("--exp-date", "-e", required=True, help="Current expiry date (YYYY-MM-DD)")
@click.option("--period", "-p", type=int, default=1, help="Renewal period")
@click.option("--period-unit", type=click.Choice(["y", "m"]), default="y", help="Period unit")
@click.pass_context
def domain_renew(ctx, name, exp_date, period, period_unit):
    """
    Renew a domain.

    NAME: Domain name to renew.
    """
    client = get_client(ctx)
    try:
        result = client.domain_renew(
            name=name,
            cur_exp_date=exp_date,
            period=period,
            period_unit=period_unit,
        )
        state.formatter.output(result)
        state.formatter.success(f"Domain renewed: {name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@domain.command("transfer")
@click.argument("name")
@click.argument("operation", type=click.Choice(["request", "query", "approve", "reject", "cancel"]))
@click.option("--auth-info", "-a", help="Auth info (required for request)")
@click.option("--period", "-p", type=int, help="Renewal period for transfer")
@click.pass_context
def domain_transfer(ctx, name, operation, auth_info, period):
    """
    Domain transfer operations.

    NAME: Domain name.
    OPERATION: Transfer operation (request, query, approve, reject, cancel).
    """
    client = get_client(ctx)
    try:
        if operation == "request":
            if not auth_info:
                print_error("Auth info required for transfer request")
                sys.exit(1)
            result = client.domain_transfer_request(name, auth_info, period=period)
            state.formatter.output(result)
        elif operation == "query":
            result = client.domain_transfer_query(name)
            state.formatter.output(result)
        elif operation == "approve":
            client.domain_transfer_approve(name)
            state.formatter.success(f"Transfer approved: {name}")
        elif operation == "reject":
            client.domain_transfer_reject(name)
            state.formatter.success(f"Transfer rejected: {name}")
        elif operation == "cancel":
            client.domain_transfer_cancel(name)
            state.formatter.success(f"Transfer cancelled: {name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@domain.command("update")
@click.argument("name")
@click.option("--add-ns", multiple=True, help="Add nameserver")
@click.option("--rem-ns", multiple=True, help="Remove nameserver")
@click.option("--add-status", multiple=True, help="Add status (e.g., clientHold)")
@click.option("--add-status-reason", multiple=True, help="Reason for add-status (same order as --add-status)")
@click.option("--rem-status", multiple=True, help="Remove status")
@click.option("--registrant", help="New registrant contact ID")
@click.option("--auth-info", help="New auth info")
@click.pass_context
def domain_update(ctx, name, add_ns, rem_ns, add_status, add_status_reason, rem_status, registrant, auth_info):
    """
    Update a domain.

    NAME: Domain name to update.

    Examples:

    \b
    # Add clientHold without reason
    epp domain update example.ae --add-status clientHold

    \b
    # Add clientHold with reason
    epp domain update example.ae --add-status clientHold --add-status-reason "Payment pending"

    \b
    # Multiple statuses with reasons
    epp domain update example.ae --add-status clientHold --add-status-reason "Under investigation" --add-status clientTransferProhibited --add-status-reason "Dispute"
    """
    client = get_client(ctx)
    try:
        # Build status list with optional reasons
        status_list = None
        if add_status:
            status_list = []
            reasons = list(add_status_reason) if add_status_reason else []
            for i, status in enumerate(add_status):
                if i < len(reasons) and reasons[i]:
                    status_list.append(StatusValue(status, reasons[i]))
                else:
                    status_list.append(status)

        client.domain_update(
            name=name,
            add_ns=list(add_ns) if add_ns else None,
            rem_ns=list(rem_ns) if rem_ns else None,
            add_status=status_list,
            rem_status=list(rem_status) if rem_status else None,
            new_registrant=registrant,
            new_auth_info=auth_info,
        )
        state.formatter.success(f"Domain updated: {name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# Contact Commands
# =============================================================================

@cli.group()
def contact():
    """Contact management commands."""
    pass


@contact.command("check")
@click.argument("ids", nargs=-1, required=True)
@click.pass_context
def contact_check(ctx, ids):
    """
    Check contact availability.

    IDS: One or more contact IDs to check.
    """
    client = get_client(ctx)
    try:
        result = client.contact_check(list(ids))
        state.formatter.output(result.results)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@contact.command("info")
@click.argument("id")
@click.option("--auth-info", "-a", help="Auth info")
@click.pass_context
def contact_info(ctx, id, auth_info):
    """
    Get contact information.

    ID: Contact ID to query.
    """
    client = get_client(ctx)
    try:
        result = client.contact_info(id, auth_info=auth_info)
        state.formatter.output(result)
    except EPPObjectNotFound:
        print_error(f"Contact not found: {id}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@contact.command("create")
@click.argument("id")
@click.option("--name", "-n", required=True, help="Contact name")
@click.option("--email", "-e", required=True, help="Email address")
@click.option("--city", "-c", required=True, help="City")
@click.option("--country", "-C", required=True, help="Country code (2-letter)")
@click.option("--org", "-o", help="Organization")
@click.option("--street", "-s", multiple=True, help="Street address (can specify multiple)")
@click.option("--state", "-S", "state_province", help="State/province")
@click.option("--postal-code", "-z", help="Postal/ZIP code")
@click.option("--voice", "-v", help="Phone number")
@click.option("--fax", "-f", help="Fax number")
@click.option("--auth-info", help="Auth info (auto-generated if not provided)")
@click.pass_context
def contact_create(ctx, id, name, email, city, country, org, street, state_province, postal_code, voice, fax, auth_info):
    """
    Create a new contact.

    ID: Contact ID to create.
    """
    client = get_client(ctx)
    try:
        result = client.contact_create(
            id=id,
            name=name,
            email=email,
            city=city,
            country_code=country,
            org=org,
            street=list(street) if street else None,
            state=state_province,
            postal_code=postal_code,
            voice=voice,
            fax=fax,
            auth_info=auth_info,
        )
        state.formatter.output(result)
        state.formatter.success(f"Contact created: {id}")
    except EPPObjectExists:
        print_error(f"Contact already exists: {id}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@contact.command("delete")
@click.argument("id")
@click.option("--confirm", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def contact_delete(ctx, id, confirm):
    """
    Delete a contact.

    ID: Contact ID to delete.
    """
    if not confirm:
        if not click.confirm(f"Are you sure you want to delete {id}?"):
            return

    client = get_client(ctx)
    try:
        client.contact_delete(id)
        state.formatter.success(f"Contact deleted: {id}")
    except EPPObjectNotFound:
        print_error(f"Contact not found: {id}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@contact.command("update")
@click.argument("id")
@click.option("--email", "-e", help="New email")
@click.option("--voice", "-v", help="New phone")
@click.option("--fax", "-f", help="New fax")
@click.option("--add-status", multiple=True, help="Add status")
@click.option("--rem-status", multiple=True, help="Remove status")
@click.option("--auth-info", help="New auth info")
@click.pass_context
def contact_update(ctx, id, email, voice, fax, add_status, rem_status, auth_info):
    """
    Update a contact.

    ID: Contact ID to update.
    """
    client = get_client(ctx)
    try:
        client.contact_update(
            id=id,
            new_email=email,
            new_voice=voice,
            new_fax=fax,
            add_status=list(add_status) if add_status else None,
            rem_status=list(rem_status) if rem_status else None,
            new_auth_info=auth_info,
        )
        state.formatter.success(f"Contact updated: {id}")
    except EPPObjectNotFound:
        print_error(f"Contact not found: {id}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@contact.command("transfer")
@click.argument("id")
@click.argument("op", type=click.Choice(["request", "approve", "reject", "cancel", "query"]))
@click.option("--auth-info", "-a", help="Authorization info (required for request)")
@click.pass_context
def contact_transfer(ctx, id, op, auth_info):
    """
    Transfer a contact between registrars.

    ID: Contact ID to transfer.

    OP: Transfer operation:
        - request: Request transfer (requires --auth-info)
        - approve: Approve incoming transfer (current registrar)
        - reject: Reject incoming transfer (current registrar)
        - cancel: Cancel outgoing transfer (requesting registrar)
        - query: Query transfer status

    Examples:

        Request transfer:
          epp contact transfer sh8013 request --auth-info 2fooBAR

        Query transfer status:
          epp contact transfer sh8013 query

        Approve transfer (current registrar):
          epp contact transfer sh8013 approve

        Reject transfer (current registrar):
          epp contact transfer sh8013 reject

        Cancel transfer (requesting registrar):
          epp contact transfer sh8013 cancel
    """
    if op == "request" and not auth_info:
        print_error("Auth info is required for transfer request")
        sys.exit(1)

    client = get_client(ctx)
    try:
        result = client.contact_transfer(
            contact_id=id,
            op=op,
            auth_info=auth_info,
        )
        if op == "request":
            state.formatter.success(f"Transfer requested for contact: {id}")
            state.formatter.output({
                "id": result.id,
                "status": result.tr_status,
                "requesting_registrar": result.re_id,
                "request_date": str(result.re_date),
                "acting_registrar": result.ac_id,
                "action_date": str(result.ac_date),
            })
        elif op == "query":
            state.formatter.output({
                "id": result.id,
                "status": result.tr_status,
                "requesting_registrar": result.re_id,
                "request_date": str(result.re_date),
                "acting_registrar": result.ac_id,
                "action_date": str(result.ac_date),
            })
        elif op == "approve":
            state.formatter.success(f"Transfer approved for contact: {id}")
        elif op == "reject":
            state.formatter.success(f"Transfer rejected for contact: {id}")
        elif op == "cancel":
            state.formatter.success(f"Transfer cancelled for contact: {id}")
    except EPPObjectNotFound:
        print_error(f"Contact not found: {id}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# Host Commands
# =============================================================================

@cli.group()
def host():
    """Host (nameserver) management commands."""
    pass


@host.command("check")
@click.argument("names", nargs=-1, required=True)
@click.pass_context
def host_check(ctx, names):
    """
    Check host availability.

    NAMES: One or more host names to check.
    """
    client = get_client(ctx)
    try:
        result = client.host_check(list(names))
        state.formatter.output(result.results)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@host.command("info")
@click.argument("name")
@click.pass_context
def host_info(ctx, name):
    """
    Get host information.

    NAME: Host name to query.
    """
    client = get_client(ctx)
    try:
        result = client.host_info(name)
        state.formatter.output(result)
    except EPPObjectNotFound:
        print_error(f"Host not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@host.command("create")
@click.argument("name")
@click.option("--ipv4", "-4", multiple=True, help="IPv4 address")
@click.option("--ipv6", "-6", multiple=True, help="IPv6 address")
@click.pass_context
def host_create(ctx, name, ipv4, ipv6):
    """
    Create a new host.

    NAME: Host name to create.
    """
    client = get_client(ctx)
    try:
        result = client.host_create(
            name=name,
            ipv4=list(ipv4) if ipv4 else None,
            ipv6=list(ipv6) if ipv6 else None,
        )
        state.formatter.output(result)
        state.formatter.success(f"Host created: {name}")
    except EPPObjectExists:
        print_error(f"Host already exists: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@host.command("delete")
@click.argument("name")
@click.option("--confirm", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def host_delete(ctx, name, confirm):
    """
    Delete a host.

    NAME: Host name to delete.
    """
    if not confirm:
        if not click.confirm(f"Are you sure you want to delete {name}?"):
            return

    client = get_client(ctx)
    try:
        client.host_delete(name)
        state.formatter.success(f"Host deleted: {name}")
    except EPPObjectNotFound:
        print_error(f"Host not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@host.command("update")
@click.argument("name")
@click.option("--add-ipv4", multiple=True, help="Add IPv4 address")
@click.option("--add-ipv6", multiple=True, help="Add IPv6 address")
@click.option("--rem-ipv4", multiple=True, help="Remove IPv4 address")
@click.option("--rem-ipv6", multiple=True, help="Remove IPv6 address")
@click.option("--add-status", multiple=True, help="Add status")
@click.option("--rem-status", multiple=True, help="Remove status")
@click.option("--new-name", help="Rename host")
@click.pass_context
def host_update(ctx, name, add_ipv4, add_ipv6, rem_ipv4, rem_ipv6, add_status, rem_status, new_name):
    """
    Update a host.

    NAME: Host name to update.
    """
    client = get_client(ctx)
    try:
        client.host_update(
            name=name,
            add_ipv4=list(add_ipv4) if add_ipv4 else None,
            add_ipv6=list(add_ipv6) if add_ipv6 else None,
            rem_ipv4=list(rem_ipv4) if rem_ipv4 else None,
            rem_ipv6=list(rem_ipv6) if rem_ipv6 else None,
            add_status=list(add_status) if add_status else None,
            rem_status=list(rem_status) if rem_status else None,
            new_name=new_name,
        )
        state.formatter.success(f"Host updated: {name}")
    except EPPObjectNotFound:
        print_error(f"Host not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# Poll Commands
# =============================================================================

@cli.group()
def poll():
    """Poll message commands."""
    pass


@poll.command("request")
@click.pass_context
def poll_request(ctx):
    """Request next poll message."""
    client = get_client(ctx)
    try:
        result = client.poll_request()
        if result:
            state.formatter.output(result)
        else:
            print_info("No messages in queue")
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@poll.command("ack")
@click.argument("msg_id")
@click.pass_context
def poll_ack(ctx, msg_id):
    """
    Acknowledge poll message.

    MSG_ID: Message ID to acknowledge.
    """
    client = get_client(ctx)
    try:
        client.poll_ack(msg_id)
        state.formatter.success(f"Message acknowledged: {msg_id}")
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# AE Extension Commands
# =============================================================================

@cli.group()
def ae():
    """AE Extension commands for .ae domains."""
    pass


@ae.command("modify-registrant")
@click.argument("domain_name")
@click.option("--registrant-name", "-n", required=True, help="Legal name of registrant")
@click.option("--explanation", "-e", required=True, help="Reason for modification (max 1000 chars)")
@click.option("--eligibility-type", "-t", help="Type of eligibility (e.g., 'Trade License')")
@click.option("--policy-reason", "-r", type=int, help="Policy reason (1-99)")
@click.option("--registrant-id", help="Registrant ID value")
@click.option("--registrant-id-type", help="Registrant ID type (e.g., 'Trade License')")
@click.option("--eligibility-name", help="Eligibility name")
@click.option("--eligibility-id", help="Eligibility ID value")
@click.option("--eligibility-id-type", help="Eligibility ID type (e.g., 'Trademark')")
@click.pass_context
def ae_modify_registrant(ctx, domain_name, registrant_name, explanation, eligibility_type,
                         policy_reason, registrant_id, registrant_id_type, eligibility_name,
                         eligibility_id, eligibility_id_type):
    """
    Modify AE extension registrant data for a .ae domain.

    This command corrects eligibility data where the legal registrant
    has NOT changed. Use to fix incorrectly specified eligibility data.

    DOMAIN_NAME: Domain name to modify (e.g., example.ae)

    \b
    Valid eligibility types:
      - Trade License
      - Freezone Trade License
      - Trademark
      - Freezone Trademark
      - Citizen
      - Government Approved
      ... and more per aeext-1.0 schema
    """
    client = get_client(ctx)
    try:
        client.ae_modify_registrant(
            domain_name=domain_name,
            registrant_name=registrant_name,
            explanation=explanation,
            eligibility_type=eligibility_type,
            policy_reason=policy_reason,
            registrant_id=registrant_id,
            registrant_id_type=registrant_id_type,
            eligibility_name=eligibility_name,
            eligibility_id=eligibility_id,
            eligibility_id_type=eligibility_id_type,
        )
        state.formatter.success(f"AE registrant data modified for: {domain_name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@ae.command("transfer-registrant")
@click.argument("domain_name")
@click.option("--cur-exp-date", "-d", required=True, help="Current expiry date (YYYY-MM-DD)")
@click.option("--registrant-name", "-n", required=True, help="New legal registrant name")
@click.option("--explanation", "-e", required=True, help="Reason for transfer (max 1000 chars)")
@click.option("--eligibility-type", "-t", required=True, help="Type of eligibility")
@click.option("--policy-reason", "-r", type=int, required=True, help="Policy reason (1-99)")
@click.option("--period", "-p", type=int, default=1, help="Validity period (default: 1)")
@click.option("--period-unit", type=click.Choice(["y", "m"]), default="y", help="Period unit")
@click.option("--registrant-id", help="Registrant ID value")
@click.option("--registrant-id-type", help="Registrant ID type")
@click.option("--eligibility-name", help="Eligibility name")
@click.option("--eligibility-id", help="Eligibility ID value")
@click.option("--eligibility-id-type", help="Eligibility ID type")
@click.option("--confirm", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def ae_transfer_registrant(ctx, domain_name, cur_exp_date, registrant_name, explanation,
                           eligibility_type, policy_reason, period, period_unit,
                           registrant_id, registrant_id_type, eligibility_name,
                           eligibility_id, eligibility_id_type, confirm):
    """
    Transfer .ae domain to a new legal registrant entity.

    This is a PROTOCOL EXTENSION command that changes legal ownership.
    A create fee will be charged and a new validity period starts.

    DOMAIN_NAME: Domain name to transfer (e.g., example.ae)

    \b
    WARNING: This operation:
      - Charges create fee to your account
      - Resets the domain validity period
      - Changes legal ownership
    """
    if not confirm:
        click.echo(f"\nThis will transfer {domain_name} to a new legal registrant.")
        click.echo("A create fee will be charged and validity period will reset.")
        if not click.confirm("\nAre you sure you want to proceed?"):
            return

    client = get_client(ctx)
    try:
        result = client.ae_transfer_registrant(
            domain_name=domain_name,
            cur_exp_date=cur_exp_date,
            registrant_name=registrant_name,
            explanation=explanation,
            eligibility_type=eligibility_type,
            policy_reason=policy_reason,
            period=period,
            period_unit=period_unit,
            registrant_id=registrant_id,
            registrant_id_type=registrant_id_type,
            eligibility_name=eligibility_name,
            eligibility_id=eligibility_id,
            eligibility_id_type=eligibility_id_type,
        )
        state.formatter.success(f"Registrant transferred for: {result.name}")
        state.formatter.output({"name": result.name, "exDate": str(result.ex_date)})
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# AR Extension Commands
# =============================================================================

@cli.group()
def ar():
    """AR Extension commands (undelete, unrenew, policyDelete)."""
    pass


@ar.command("undelete")
@click.argument("domain_name")
@click.pass_context
def ar_undelete(ctx, domain_name):
    """
    Restore a deleted domain from redemption grace period.

    DOMAIN_NAME: Domain name to restore (e.g., example.ae)

    This command restores a domain that is in pending delete or
    redemption status back to active status.
    """
    client = get_client(ctx)
    try:
        result = client.ar_undelete(domain_name)
        state.formatter.success(f"Domain restored: {result.name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@ar.command("unrenew")
@click.argument("domain_name")
@click.pass_context
def ar_unrenew(ctx, domain_name):
    """
    Cancel a pending domain renewal.

    DOMAIN_NAME: Domain name to unrenew (e.g., example.ae)

    This command reverts a recent renewal, restoring the previous
    expiry date. The renewal fee will be refunded.
    """
    client = get_client(ctx)
    try:
        result = client.ar_unrenew(domain_name)
        state.formatter.success(f"Renewal cancelled for: {result.name}")
        state.formatter.output({"name": result.name, "exDate": str(result.ex_date)})
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@ar.command("policy-delete")
@click.argument("domain_name")
@click.option("--reason", "-r", help="Reason for policy deletion")
@click.option("--confirm", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def ar_policy_delete(ctx, domain_name, reason, confirm):
    """
    Delete a domain due to policy violation.

    DOMAIN_NAME: Domain name to delete (e.g., example.ae)

    This command is for registry-initiated or policy-based domain deletion.
    The domain will be deleted immediately without a grace period.
    """
    if not confirm:
        click.echo(f"\nThis will immediately delete {domain_name} for policy violation.")
        click.echo("This action cannot be undone through normal means.")
        if not click.confirm("\nAre you sure you want to proceed?"):
            return

    client = get_client(ctx)
    try:
        client.ar_policy_delete(domain_name, reason=reason)
        state.formatter.success(f"Domain deleted for policy violation: {domain_name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# ENUM/E.164 Extension Commands
# =============================================================================

@cli.group()
def enum():
    """ENUM (E.164) Extension commands for telephone number mapping."""
    pass


@enum.command("create")
@click.argument("domain_name")
@click.option("--registrant", "-r", required=True, help="Registrant contact ID")
@click.option("--naptr", "-n", multiple=True, required=True,
              help="NAPTR record: order,pref,flags,svc,regex (e.g., '100,10,u,E2U+sip,!^.*$!sip:user@example.com!')")
@click.option("--admin", "-a", help="Admin contact ID")
@click.option("--tech", "-t", help="Tech contact ID")
@click.option("--billing", "-b", help="Billing contact ID")
@click.option("--ns", multiple=True, help="Nameserver (can specify multiple)")
@click.option("--period", "-p", type=int, default=1, help="Registration period")
@click.option("--period-unit", type=click.Choice(["y", "m"]), default="y", help="Period unit")
@click.option("--auth-info", help="Auth info (auto-generated if not provided)")
@click.pass_context
def enum_create(ctx, domain_name, registrant, naptr, admin, tech, billing, ns, period, period_unit, auth_info):
    """
    Create an ENUM domain with NAPTR records.

    DOMAIN_NAME: ENUM domain name (e.g., 1.2.3.4.5.6.7.8.9.0.9.4.e164.arpa)

    NAPTR records map telephone numbers to internet services.

    \b
    NAPTR format: order,pref,flags,svc,regex
      - order: Processing order (lower first)
      - pref: Preference (breaks ties)
      - flags: Single char, 'u' for terminal rule
      - svc: Service type (E2U+sip, E2U+mailto, E2U+tel, etc.)
      - regex: URI transformation regex

    \b
    Common service types:
      - E2U+sip: SIP URI
      - E2U+tel: Tel URI
      - E2U+mailto: Email URI
      - E2U+http: HTTP URI

    \b
    Examples:
      epp enum create 1.2.3.4.5.6.7.8.9.0.9.4.e164.arpa -r contact123 \\
          -n "100,10,u,E2U+sip,!^.*$!sip:user@example.com!" \\
          -n "100,20,u,E2U+mailto,!^.*$!mailto:user@example.com!"
    """
    # Parse NAPTR records from CLI format
    naptr_records = []
    for record in naptr:
        parts = record.split(",", 4)
        if len(parts) < 4:
            print_error(f"Invalid NAPTR format: {record}. Expected: order,pref,flags,svc[,regex]")
            sys.exit(1)

        naptr_dict = {
            "order": int(parts[0]),
            "pref": int(parts[1]),
            "svc": parts[3],
        }
        if parts[2]:  # flags can be empty
            naptr_dict["flags"] = parts[2]
        if len(parts) > 4 and parts[4]:
            naptr_dict["regex"] = parts[4]

        naptr_records.append(naptr_dict)

    client = get_client(ctx)
    try:
        result = client.enum_domain_create(
            name=domain_name,
            registrant=registrant,
            naptr_records=naptr_records,
            period=period,
            period_unit=period_unit,
            admin=admin,
            tech=tech,
            billing=billing,
            nameservers=list(ns) if ns else None,
            auth_info=auth_info,
        )
        state.formatter.output(result)
        state.formatter.success(f"ENUM domain created: {domain_name}")
    except EPPObjectExists:
        print_error(f"Domain already exists: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@enum.command("info")
@click.argument("domain_name")
@click.option("--auth-info", "-a", help="Auth info for transfer query")
@click.pass_context
def enum_info(ctx, domain_name, auth_info):
    """
    Get ENUM domain information including NAPTR records.

    DOMAIN_NAME: ENUM domain name to query.
    """
    client = get_client(ctx)
    try:
        domain_info, e164_info = client.enum_domain_info(domain_name, auth_info=auth_info)

        # Output domain info
        state.formatter.output(domain_info)

        # Output NAPTR records if present
        if e164_info and e164_info.naptr_records:
            print_info("\nNAPTR Records:")
            for record in e164_info.naptr_records:
                print_info(f"  Order: {record.order}, Pref: {record.pref}, "
                          f"Flags: {record.flags or ''}, Service: {record.svc}")
                if record.regex:
                    print_info(f"    Regex: {record.regex}")
                if record.repl:
                    print_info(f"    Repl: {record.repl}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@enum.command("update")
@click.argument("domain_name")
@click.option("--add-naptr", "-a", multiple=True,
              help="NAPTR to add: order,pref,flags,svc,regex")
@click.option("--rem-naptr", "-r", multiple=True,
              help="NAPTR to remove: order,pref,flags,svc,regex")
@click.option("--add-ns", multiple=True, help="Add nameserver")
@click.option("--rem-ns", multiple=True, help="Remove nameserver")
@click.option("--registrant", help="New registrant contact ID")
@click.option("--auth-info", help="New auth info")
@click.pass_context
def enum_update(ctx, domain_name, add_naptr, rem_naptr, add_ns, rem_ns, registrant, auth_info):
    """
    Update an ENUM domain (add/remove NAPTR records).

    DOMAIN_NAME: ENUM domain name to update.

    \b
    Examples:
      # Add a new NAPTR record
      epp enum update 1.2.3.4.5.6.7.8.9.0.9.4.e164.arpa \\
          --add-naptr "100,5,u,E2U+sip,!^.*$!sip:new@example.com!"

      # Remove a NAPTR record (must match exactly)
      epp enum update 1.2.3.4.5.6.7.8.9.0.9.4.e164.arpa \\
          --rem-naptr "100,10,u,E2U+sip,!^.*$!sip:old@example.com!"
    """
    # Parse NAPTR records to add
    add_records = None
    if add_naptr:
        add_records = []
        for record in add_naptr:
            parts = record.split(",", 4)
            if len(parts) < 4:
                print_error(f"Invalid NAPTR format: {record}")
                sys.exit(1)
            naptr_dict = {
                "order": int(parts[0]),
                "pref": int(parts[1]),
                "svc": parts[3],
            }
            if parts[2]:
                naptr_dict["flags"] = parts[2]
            if len(parts) > 4 and parts[4]:
                naptr_dict["regex"] = parts[4]
            add_records.append(naptr_dict)

    # Parse NAPTR records to remove
    rem_records = None
    if rem_naptr:
        rem_records = []
        for record in rem_naptr:
            parts = record.split(",", 4)
            if len(parts) < 4:
                print_error(f"Invalid NAPTR format: {record}")
                sys.exit(1)
            naptr_dict = {
                "order": int(parts[0]),
                "pref": int(parts[1]),
                "svc": parts[3],
            }
            if parts[2]:
                naptr_dict["flags"] = parts[2]
            if len(parts) > 4 and parts[4]:
                naptr_dict["regex"] = parts[4]
            rem_records.append(naptr_dict)

    client = get_client(ctx)
    try:
        client.enum_domain_update(
            name=domain_name,
            add_naptr=add_records,
            rem_naptr=rem_records,
            add_ns=list(add_ns) if add_ns else None,
            rem_ns=list(rem_ns) if rem_ns else None,
            new_registrant=registrant,
            new_auth_info=auth_info,
        )
        state.formatter.success(f"ENUM domain updated: {domain_name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# AU Extension Commands
# =============================================================================

@cli.group()
def au():
    """AU Extension commands for .au domains."""
    pass


@au.command("modify-registrant")
@click.argument("domain_name")
@click.option("--registrant-name", "-n", required=True, help="Legal name of registrant")
@click.option("--explanation", "-e", required=True, help="Reason for modification (max 1000 chars)")
@click.option("--eligibility-type", "-t", required=True, help="Type of eligibility (e.g., 'Company')")
@click.option("--policy-reason", "-r", type=int, required=True, help="Policy reason (1-106)")
@click.option("--registrant-id", help="Registrant ID value (e.g., ACN number)")
@click.option("--registrant-id-type", type=click.Choice(["ACN", "ABN", "OTHER"]), help="Registrant ID type")
@click.option("--eligibility-name", help="Eligibility name")
@click.option("--eligibility-id", help="Eligibility ID value")
@click.option("--eligibility-id-type", help="Eligibility ID type (ACN, ABN, TM, etc.)")
@click.pass_context
def au_modify_registrant(ctx, domain_name, registrant_name, explanation, eligibility_type,
                         policy_reason, registrant_id, registrant_id_type, eligibility_name,
                         eligibility_id, eligibility_id_type):
    """
    Modify AU extension registrant data for a .au domain.

    This command corrects eligibility data where the legal registrant
    has NOT changed. Use to fix incorrectly specified eligibility data.

    DOMAIN_NAME: Domain name to modify (e.g., example.com.au)

    \b
    Valid eligibility types include:
      - Charity
      - Citizen/Resident
      - Club
      - Company
      - Incorporated Association
      - Partnership
      - Pending TM Owner
      - Registered Business
      - Religious/Church Group
      - Sole Trader
      - TM Owner
      - Trade Union
      ... and more per auext-1.1 schema

    \b
    Valid registrant ID types:
      - ACN: Australian Company Number
      - ABN: Australian Business Number
      - OTHER: Other identifier

    \b
    Valid eligibility ID types:
      - ACN, ABN
      - VIC BN, NSW BN, SA BN, NT BN, WA BN, TAS BN, ACT BN, QLD BN
      - TM: Trademark
      - OTHER
    """
    client = get_client(ctx)
    try:
        client.au_modify_registrant(
            domain_name=domain_name,
            registrant_name=registrant_name,
            explanation=explanation,
            eligibility_type=eligibility_type,
            policy_reason=policy_reason,
            registrant_id=registrant_id,
            registrant_id_type=registrant_id_type,
            eligibility_name=eligibility_name,
            eligibility_id=eligibility_id,
            eligibility_id_type=eligibility_id_type,
        )
        state.formatter.success(f"AU registrant data modified for: {domain_name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@au.command("transfer-registrant")
@click.argument("domain_name")
@click.option("--cur-exp-date", "-d", required=True, help="Current expiry date (YYYY-MM-DD)")
@click.option("--registrant-name", "-n", required=True, help="New legal registrant name")
@click.option("--explanation", "-e", required=True, help="Reason for transfer (max 1000 chars)")
@click.option("--eligibility-type", "-t", required=True, help="Type of eligibility")
@click.option("--policy-reason", "-r", type=int, required=True, help="Policy reason (1-106)")
@click.option("--period", "-p", type=int, default=1, help="Validity period (default: 1)")
@click.option("--period-unit", type=click.Choice(["y", "m"]), default="y", help="Period unit")
@click.option("--registrant-id", help="Registrant ID value")
@click.option("--registrant-id-type", type=click.Choice(["ACN", "ABN", "OTHER"]), help="Registrant ID type")
@click.option("--eligibility-name", help="Eligibility name")
@click.option("--eligibility-id", help="Eligibility ID value")
@click.option("--eligibility-id-type", help="Eligibility ID type")
@click.option("--confirm", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def au_transfer_registrant(ctx, domain_name, cur_exp_date, registrant_name, explanation,
                           eligibility_type, policy_reason, period, period_unit,
                           registrant_id, registrant_id_type, eligibility_name,
                           eligibility_id, eligibility_id_type, confirm):
    """
    Transfer .au domain to a new legal registrant entity.

    This is a PROTOCOL EXTENSION command that changes legal ownership.
    A create fee will be charged and a new validity period starts.

    DOMAIN_NAME: Domain name to transfer (e.g., example.com.au)

    \b
    WARNING: This operation:
      - Charges create fee to your account
      - Resets the domain validity period
      - Changes legal ownership
    """
    if not confirm:
        click.echo(f"\nThis will transfer {domain_name} to a new legal registrant.")
        click.echo("A create fee will be charged and validity period will reset.")
        if not click.confirm("\nAre you sure you want to proceed?"):
            return

    client = get_client(ctx)
    try:
        result = client.au_transfer_registrant(
            domain_name=domain_name,
            cur_exp_date=cur_exp_date,
            registrant_name=registrant_name,
            explanation=explanation,
            eligibility_type=eligibility_type,
            policy_reason=policy_reason,
            period=period,
            period_unit=period_unit,
            registrant_id=registrant_id,
            registrant_id_type=registrant_id_type,
            eligibility_name=eligibility_name,
            eligibility_id=eligibility_id,
            eligibility_id_type=eligibility_id_type,
        )
        state.formatter.success(f"Registrant transferred for: {result.name}")
        state.formatter.output({"name": result.name, "exDate": str(result.ex_date)})
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# DNSSEC Extension Commands
# =============================================================================

@cli.group()
def dnssec():
    """DNSSEC (secDNS) Extension commands."""
    pass


@dnssec.command("info")
@click.argument("domain_name")
@click.option("--auth-info", "-a", help="Auth info for transfer query")
@click.pass_context
def dnssec_info(ctx, domain_name, auth_info):
    """
    Get domain DNSSEC information.

    DOMAIN_NAME: Domain name to query.
    """
    client = get_client(ctx)
    try:
        domain_info, secdns_info = client.domain_info_secdns(domain_name, auth_info=auth_info)

        state.formatter.output(domain_info)

        if secdns_info:
            print_info("\nDNSSEC Data:")
            if secdns_info.max_sig_life:
                print_info(f"  Max Signature Life: {secdns_info.max_sig_life}s")

            if secdns_info.ds_data:
                print_info("  DS Records:")
                for ds in secdns_info.ds_data:
                    print_info(f"    KeyTag: {ds.key_tag}, Alg: {ds.alg}, DigestType: {ds.digest_type}")
                    print_info(f"      Digest: {ds.digest[:40]}...")

            if secdns_info.key_data:
                print_info("  Key Records:")
                for key in secdns_info.key_data:
                    print_info(f"    Flags: {key.flags}, Protocol: {key.protocol}, Alg: {key.alg}")
        else:
            print_info("\nNo DNSSEC data for this domain.")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@dnssec.command("add")
@click.argument("domain_name")
@click.option("--ds", "-d", multiple=True,
              help="DS record: keyTag,alg,digestType,digest (e.g., '12345,8,2,49FD46E6...')")
@click.option("--key", "-k", multiple=True,
              help="Key record: flags,protocol,alg,pubKey (e.g., '257,3,8,AwEAAa...')")
@click.pass_context
def dnssec_add(ctx, domain_name, ds, key):
    """
    Add DNSSEC records to a domain.

    DOMAIN_NAME: Domain name to update.

    \b
    DS record format: keyTag,alg,digestType,digest
      - keyTag: 0-65535 (unsigned short)
      - alg: Algorithm number (5, 7, 8, 10, 13, 14, 15, 16)
      - digestType: 1=SHA-1, 2=SHA-256, 4=SHA-384
      - digest: Hex-encoded digest

    \b
    Key record format: flags,protocol,alg,pubKey
      - flags: 256=ZSK, 257=KSK
      - protocol: Always 3 for DNSSEC
      - alg: Algorithm number
      - pubKey: Base64-encoded public key

    \b
    Examples:
      epp dnssec add example.ae --ds "12345,8,2,49FD46E6C4B45C55D4AC"
      epp dnssec add example.ae --key "257,3,8,AwEAAagAIKlVZr..."
    """
    add_ds = []
    for record in ds:
        parts = record.split(",", 3)
        if len(parts) != 4:
            print_error(f"Invalid DS format: {record}. Expected: keyTag,alg,digestType,digest")
            sys.exit(1)
        add_ds.append({
            "key_tag": int(parts[0]),
            "alg": int(parts[1]),
            "digest_type": int(parts[2]),
            "digest": parts[3],
        })

    add_key = []
    for record in key:
        parts = record.split(",", 3)
        if len(parts) != 4:
            print_error(f"Invalid Key format: {record}. Expected: flags,protocol,alg,pubKey")
            sys.exit(1)
        add_key.append({
            "flags": int(parts[0]),
            "protocol": int(parts[1]),
            "alg": int(parts[2]),
            "pub_key": parts[3],
        })

    if not add_ds and not add_key:
        print_error("At least one --ds or --key option is required")
        sys.exit(1)

    client = get_client(ctx)
    try:
        client.domain_update_secdns(
            name=domain_name,
            add_ds=add_ds if add_ds else None,
            add_key=add_key if add_key else None,
        )
        state.formatter.success(f"DNSSEC records added to: {domain_name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@dnssec.command("remove")
@click.argument("domain_name")
@click.option("--ds", "-d", multiple=True,
              help="DS record to remove: keyTag,alg,digestType,digest")
@click.option("--key", "-k", multiple=True,
              help="Key record to remove: flags,protocol,alg,pubKey")
@click.option("--all", "rem_all", is_flag=True, help="Remove all DNSSEC data")
@click.option("--confirm", "-y", is_flag=True, help="Skip confirmation for --all")
@click.pass_context
def dnssec_remove(ctx, domain_name, ds, key, rem_all, confirm):
    """
    Remove DNSSEC records from a domain.

    DOMAIN_NAME: Domain name to update.

    Use --all to remove all DNSSEC data at once.
    """
    if rem_all and not confirm:
        if not click.confirm(f"Remove ALL DNSSEC data from {domain_name}?"):
            return

    rem_ds = []
    for record in ds:
        parts = record.split(",", 3)
        if len(parts) != 4:
            print_error(f"Invalid DS format: {record}")
            sys.exit(1)
        rem_ds.append({
            "key_tag": int(parts[0]),
            "alg": int(parts[1]),
            "digest_type": int(parts[2]),
            "digest": parts[3],
        })

    rem_key = []
    for record in key:
        parts = record.split(",", 3)
        if len(parts) != 4:
            print_error(f"Invalid Key format: {record}")
            sys.exit(1)
        rem_key.append({
            "flags": int(parts[0]),
            "protocol": int(parts[1]),
            "alg": int(parts[2]),
            "pub_key": parts[3],
        })

    if not rem_all and not rem_ds and not rem_key:
        print_error("Specify --ds, --key, or --all")
        sys.exit(1)

    client = get_client(ctx)
    try:
        client.domain_update_secdns(
            name=domain_name,
            rem_ds=rem_ds if rem_ds else None,
            rem_key=rem_key if rem_key else None,
            rem_all=rem_all,
        )
        state.formatter.success(f"DNSSEC records removed from: {domain_name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# IDN Extension Commands
# =============================================================================

@cli.group()
def idn():
    """IDN (Internationalized Domain Names) Extension commands."""
    pass


@idn.command("create")
@click.argument("domain_name")
@click.option("--registrant", "-r", required=True, help="Registrant contact ID")
@click.option("--user-form", "-u", required=True, help="Unicode user form (e.g., 'مثال')")
@click.option("--language", "-l", required=True, help="BCP 47 language tag (e.g., 'ar', 'zh', 'de')")
@click.option("--admin", "-a", help="Admin contact ID")
@click.option("--tech", "-t", help="Tech contact ID")
@click.option("--ns", multiple=True, help="Nameserver")
@click.option("--period", "-p", type=int, default=1, help="Registration period")
@click.pass_context
def idn_create(ctx, domain_name, registrant, user_form, language, admin, tech, ns, period):
    """
    Create an IDN domain with user form.

    DOMAIN_NAME: DNS/ACE form domain name (e.g., xn--mgbh0fb.ae)

    \b
    Examples:
      # Arabic domain
      epp idn create xn--mgbh0fb.ae -r contact123 -u "مثال" -l ar

      # German domain
      epp idn create xn--mnchen-3ya.de -r contact123 -u "münchen" -l de
    """
    client = get_client(ctx)
    try:
        result, idn_data = client.domain_create_with_idn(
            name=domain_name,
            registrant=registrant,
            user_form=user_form,
            language=language,
            period=period,
            admin=admin,
            tech=tech,
            nameservers=list(ns) if ns else None,
        )
        state.formatter.output(result)
        if idn_data and idn_data.canonical_form:
            print_info(f"Canonical form: {idn_data.canonical_form}")
        state.formatter.success(f"IDN domain created: {domain_name}")
    except EPPObjectExists:
        print_error(f"Domain already exists: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@idn.command("info")
@click.argument("domain_name")
@click.pass_context
def idn_info(ctx, domain_name):
    """
    Get IDN domain information including user form.

    DOMAIN_NAME: Domain name to query.
    """
    client = get_client(ctx)
    try:
        domain_info, idn_data = client.domain_info_idn(domain_name)
        state.formatter.output(domain_info)

        if idn_data:
            print_info("\nIDN Data:")
            print_info(f"  User Form: {idn_data.user_form}")
            print_info(f"  Language: {idn_data.language}")
            if idn_data.canonical_form:
                print_info(f"  Canonical Form: {idn_data.canonical_form}")
        else:
            print_info("\nNo IDN data for this domain.")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# Variant Extension Commands
# =============================================================================

@cli.group()
def variant():
    """Domain Variant Extension commands."""
    pass


@variant.command("info")
@click.argument("domain_name")
@click.option("--variants", "-v", type=click.Choice(["all", "none"]), default="all",
              help="Variant query type")
@click.pass_context
def variant_info(ctx, domain_name, variants):
    """
    Get domain variant information.

    DOMAIN_NAME: Domain name to query.
    """
    client = get_client(ctx)
    try:
        domain_info, variant_info = client.domain_info_variants(domain_name, variants=variants)
        state.formatter.output(domain_info)

        if variant_info and variant_info.variants:
            print_info("\nVariants:")
            for var in variant_info.variants:
                print_info(f"  {var.name} ({var.user_form})")
        else:
            print_info("\nNo variants for this domain.")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@variant.command("add")
@click.argument("domain_name")
@click.option("--variant", "-v", multiple=True, required=True,
              help="Variant to add: dnsForm,userForm (e.g., 'xn--fsqu00a,例子')")
@click.pass_context
def variant_add(ctx, domain_name, variant):
    """
    Add variants to a domain.

    DOMAIN_NAME: Domain name to update.
    """
    add_variants = []
    for v in variant:
        parts = v.split(",", 1)
        if len(parts) != 2:
            print_error(f"Invalid variant format: {v}. Expected: dnsForm,userForm")
            sys.exit(1)
        add_variants.append({"name": parts[0], "user_form": parts[1]})

    client = get_client(ctx)
    try:
        client.domain_update_variants(domain_name, add_variants=add_variants)
        state.formatter.success(f"Variants added to: {domain_name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@variant.command("remove")
@click.argument("domain_name")
@click.option("--variant", "-v", multiple=True, required=True,
              help="Variant DNS form to remove")
@click.pass_context
def variant_remove(ctx, domain_name, variant):
    """
    Remove variants from a domain.

    DOMAIN_NAME: Domain name to update.
    """
    client = get_client(ctx)
    try:
        client.domain_update_variants(domain_name, rem_variants=list(variant))
        state.formatter.success(f"Variants removed from: {domain_name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# Sync Extension Commands
# =============================================================================

@domain.command("sync")
@click.argument("domain_name")
@click.option("--exp-date", "-e", required=True,
              help="Target expiry date (YYYY-MM-DDTHH:MM:SS.0Z or YYYY-MM-DD)")
@click.pass_context
def domain_sync_cmd(ctx, domain_name, exp_date):
    """
    Synchronize domain expiry date.

    DOMAIN_NAME: Domain name to sync.

    This command adjusts the domain expiry date to match a target date.
    Billing adjustments will be applied accordingly.

    \b
    Examples:
      epp domain sync example.ae --exp-date 2025-12-31
      epp domain sync example.ae --exp-date 2025-12-31T23:59:59.0Z
    """
    # Normalize date format
    if "T" not in exp_date:
        exp_date = f"{exp_date}T23:59:59.0Z"

    client = get_client(ctx)
    try:
        client.domain_sync(domain_name, exp_date)
        state.formatter.success(f"Domain expiry synchronized: {domain_name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# KV Extension Commands
# =============================================================================

@cli.group()
def kv():
    """Key-Value Extension commands for domain metadata."""
    pass


@kv.command("info")
@click.argument("domain_name")
@click.pass_context
def kv_info(ctx, domain_name):
    """
    Get domain key-value metadata.

    DOMAIN_NAME: Domain name to query.
    """
    client = get_client(ctx)
    try:
        domain_info, kv_info = client.domain_info_kv(domain_name)
        state.formatter.output(domain_info)

        if kv_info and kv_info.kvlists:
            print_info("\nKey-Value Lists:")
            for kvlist in kv_info.kvlists:
                print_info(f"  [{kvlist.name}]")
                for item in kvlist.items:
                    print_info(f"    {item.key} = {item.value}")
        else:
            print_info("\nNo key-value data for this domain.")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@kv.command("set")
@click.argument("domain_name")
@click.option("--list", "-l", "list_name", required=True, help="List name (e.g., 'metadata')")
@click.option("--item", "-i", multiple=True, required=True,
              help="Key-value item: key=value")
@click.pass_context
def kv_set(ctx, domain_name, list_name, item):
    """
    Set key-value metadata for a domain.

    DOMAIN_NAME: Domain name to update.

    \b
    Examples:
      epp kv set example.ae -l metadata -i "category=premium" -i "source=auction"
    """
    items = []
    for i in item:
        parts = i.split("=", 1)
        if len(parts) != 2:
            print_error(f"Invalid item format: {i}. Expected: key=value")
            sys.exit(1)
        items.append({"key": parts[0], "value": parts[1]})

    kvlists = [{"name": list_name, "items": items}]

    client = get_client(ctx)
    try:
        client.domain_update_kv(domain_name, kvlists)
        state.formatter.success(f"Key-value data updated for: {domain_name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {domain_name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Main entry point."""
    try:
        cli()
    except EPPError as e:
        print_error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
