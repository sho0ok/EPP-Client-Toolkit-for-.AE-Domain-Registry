# EPP XML Command Templates

RFC 5730-5734 compliant XML templates for use with the `epp raw` command.

## Usage

```bash
# Send a template directly
epp raw --file xml-templates/domain/check.xml

# Pretty-print the response
epp raw --file xml-templates/domain/info.xml --pretty

# Copy a template, edit it, then send
cp xml-templates/domain/create-co-ae.xml /tmp/my-domain.xml
# (edit /tmp/my-domain.xml with your values)
epp raw --file /tmp/my-domain.xml --pretty

# Send with a custom clTRID
epp raw --file xml-templates/domain/check.xml --cltrid "MY.20260208.001"

# Send login XML manually (skip auto-login)
epp raw --no-login --file xml-templates/session/login.xml

# Pipe from stdin
cat xml-templates/domain/check.xml | epp raw --stdin
```

## Template Structure

```
xml-templates/
  session/
    hello.xml               # Server greeting request
    login.xml               # Session login
    logout.xml              # Session logout
    poll-request.xml        # Poll message queue
    poll-ack.xml            # Acknowledge poll message

  domain/
    check.xml               # Check domain availability
    info.xml                # Query domain details
    info-with-auth.xml      # Query with auth (full details)
    create.xml              # Create .ae domain (no extension)
    create-co-ae.xml        # Create .co.ae (Trade License)
    create-net-ae.xml       # Create .net.ae (IT types only)
    create-org-ae.xml       # Create .org.ae (organisations)
    create-gov-ae.xml       # Create .gov.ae (policy-reason 5)
    create-mil-ae.xml       # Create .mil.ae (policy-reason 5)
    create-sch-ae.xml       # Create .sch.ae (schools)
    create-ac-ae.xml        # Create .ac.ae (academic)
    create-idn.xml          # Create IDN domain (.امارات)
    create-dnssec.xml       # Create with DNSSEC DS data
    delete.xml              # Delete domain
    renew.xml               # Renew domain
    transfer-request.xml    # Request transfer (gaining registrar)
    transfer-query.xml      # Query transfer status
    transfer-approve.xml    # Approve transfer (losing registrar)
    transfer-reject.xml     # Reject transfer (losing registrar)
    transfer-cancel.xml     # Cancel transfer (gaining registrar)
    update.xml              # Update domain (add/rem/chg)
    update-dnssec.xml       # Update DNSSEC DS data
    update-sync.xml         # Synchronize expiry date

  contact/
    check.xml               # Check contact availability
    info.xml                # Query contact details
    create.xml              # Create contact
    delete.xml              # Delete contact
    update.xml              # Update contact
    transfer-request.xml    # Request contact transfer
    transfer-approve.xml    # Approve/reject/cancel transfer

  host/
    check.xml               # Check host availability
    info.xml                # Query host details
    create.xml              # Create host (with glue records)
    delete.xml              # Delete host
    update.xml              # Update host (add/rem/chg)

  extensions/
    ar-undelete.xml         # AR: Undelete domain
    ar-unrenew.xml          # AR: Unrenew domain
    ar-policy-delete.xml    # AR: Policy delete
    ar-policy-undelete.xml  # AR: Policy undelete
    ae-registrant-transfer.xml  # AE: Registrant transfer
    domain-create-kv.xml    # KV: Create with key-value data
    domain-info-variant.xml # Variant: Info with variants
```

## Placeholder Values

Templates use UPPERCASE placeholder values that you must replace:

| Placeholder | Description |
|-------------|-------------|
| `REGISTRANT_ID` | Contact ID for domain registrant |
| `TECH_CONTACT_ID` | Contact ID for technical contact |
| `ADMIN_CONTACT_ID` | Contact ID for admin contact |
| `DOMAIN_PASSWORD` | Domain auth info password |
| `CONTACT_PASSWORD` | Contact auth info password |
| `REGISTRAR_ID` | Your registrar/client ID |
| `PASSWORD` | Your registrar password |
| `MESSAGE_ID` | Poll message ID to acknowledge |

## Password Requirements

ARI requires auth info passwords with:
- Minimum 8 characters
- At least 2 uppercase letters (A-Z)
- At least 2 lowercase letters (a-z)
- At least 2 digits (0-9)
- At least 2 special characters (!@#$%^&*()?)

Example: `Ab12!@Cd34#$Ef56`

## XML Namespaces Reference

| Prefix | URI | RFC/Spec |
|--------|-----|----------|
| epp | `urn:ietf:params:xml:ns:epp-1.0` | RFC 5730 |
| domain | `urn:ietf:params:xml:ns:domain-1.0` | RFC 5731 |
| contact | `urn:ietf:params:xml:ns:contact-1.0` | RFC 5733 |
| host | `urn:ietf:params:xml:ns:host-1.0` | RFC 5732 |
| aeext | `urn:X-ae:params:xml:ns:aeext-1.0` | AE Extension 1.0 |
| arext | `urn:X-ar:params:xml:ns:arext-1.0` | AR Extension 1.0 |
| secDNS | `urn:ietf:params:xml:ns:secDNS-1.1` | RFC 5910 |
| idnadomain | `urn:X-ar:params:xml:ns:idnadomain-1.0` | IDN Extension |
| variant | `urn:X-ar:params:xml:ns:variant-1.0` | Variant Extension |
| sync | `urn:X-ar:params:xml:ns:sync-1.0` | Sync Extension |
| kv | `urn:X-ar:params:xml:ns:kv-1.0` | Key-Value Extension |
