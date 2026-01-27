"""
EPP XML Builder

Builds EPP XML commands per RFC 5730-5733.
"""

import secrets
import string
from datetime import datetime
from typing import Any, Dict, List, Optional

from lxml import etree

from epp_client.models import (
    DomainCreate,
    DomainUpdate,
    DomainContact,
    ContactCreate,
    ContactUpdate,
    PostalInfo,
    HostCreate,
    HostUpdate,
    HostAddress,
    StatusValue,
)

# EPP Namespaces
NS = {
    "epp": "urn:ietf:params:xml:ns:epp-1.0",
    "domain": "urn:ietf:params:xml:ns:domain-1.0",
    "contact": "urn:ietf:params:xml:ns:contact-1.0",
    "host": "urn:ietf:params:xml:ns:host-1.0",
}

# Namespace URIs
EPP_NS = "urn:ietf:params:xml:ns:epp-1.0"
DOMAIN_NS = "urn:ietf:params:xml:ns:domain-1.0"
CONTACT_NS = "urn:ietf:params:xml:ns:contact-1.0"
HOST_NS = "urn:ietf:params:xml:ns:host-1.0"

# Extension Namespaces
AEEXT_NS = "urn:X-ae:params:xml:ns:aeext-1.0"
AREXT_NS = "urn:X-ar:params:xml:ns:arext-1.0"
AUEXT_NS = "urn:X-au:params:xml:ns:auext-1.1"
E164_NS = "urn:ietf:params:xml:ns:e164epp-1.0"
SECDNS_NS = "urn:ietf:params:xml:ns:secDNS-1.1"
IDN_NS = "urn:X-ar:params:xml:ns:idnadomain-1.0"
VARIANT_NS = "urn:X-ar:params:xml:ns:variant-1.0"
SYNC_NS = "urn:X-ar:params:xml:ns:sync-1.0"
KV_NS = "urn:X-ar:params:xml:ns:kv-1.0"


def _generate_cl_trid() -> str:
    """Generate client transaction ID."""
    chars = string.ascii_uppercase + string.digits
    random_part = ''.join(secrets.choice(chars) for _ in range(8))
    return f"CLI-{random_part}"


def _generate_auth_info(length: int = 16) -> str:
    """Generate random auth info."""
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(secrets.choice(chars) for _ in range(length))


def _create_epp_root() -> etree._Element:
    """Create EPP root element with namespaces."""
    nsmap = {
        None: EPP_NS,
        "domain": DOMAIN_NS,
        "contact": CONTACT_NS,
        "host": HOST_NS,
    }
    return etree.Element("{%s}epp" % EPP_NS, nsmap=nsmap)


def _add_cl_trid(command: etree._Element, cl_trid: str = None) -> None:
    """Add client transaction ID to command."""
    if cl_trid is None:
        cl_trid = _generate_cl_trid()
    etree.SubElement(command, "{%s}clTRID" % EPP_NS).text = cl_trid


# AE Eligibility namespace
AE_ELIGIBILITY_NS = "urn:aeda:params:xml:ns:aeEligibility-1.0"


def _add_ae_eligibility_extension(command: etree._Element, eligibility) -> None:
    """Add AE Eligibility extension to command."""
    extension = etree.SubElement(command, "{%s}extension" % EPP_NS)

    ae_create = etree.Element(
        "{%s}create" % AE_ELIGIBILITY_NS,
        nsmap={"aeEligibility": AE_ELIGIBILITY_NS}
    )

    # Add eligibility fields
    if eligibility.eligibility_type:
        etree.SubElement(ae_create, "{%s}eligibilityType" % AE_ELIGIBILITY_NS).text = eligibility.eligibility_type

    if eligibility.eligibility_name:
        etree.SubElement(ae_create, "{%s}eligibilityName" % AE_ELIGIBILITY_NS).text = eligibility.eligibility_name

    if eligibility.eligibility_id:
        etree.SubElement(ae_create, "{%s}eligibilityID" % AE_ELIGIBILITY_NS).text = eligibility.eligibility_id

    if eligibility.eligibility_id_type:
        etree.SubElement(ae_create, "{%s}eligibilityIDType" % AE_ELIGIBILITY_NS).text = eligibility.eligibility_id_type

    if eligibility.policy_reason is not None:
        etree.SubElement(ae_create, "{%s}policyReason" % AE_ELIGIBILITY_NS).text = str(eligibility.policy_reason)

    if eligibility.registrant_id:
        etree.SubElement(ae_create, "{%s}registrantID" % AE_ELIGIBILITY_NS).text = eligibility.registrant_id

    if eligibility.registrant_id_type:
        etree.SubElement(ae_create, "{%s}registrantIDType" % AE_ELIGIBILITY_NS).text = eligibility.registrant_id_type

    if eligibility.registrant_name:
        etree.SubElement(ae_create, "{%s}registrantName" % AE_ELIGIBILITY_NS).text = eligibility.registrant_name

    extension.append(ae_create)


def _to_bytes(root: etree._Element) -> bytes:
    """Convert element tree to XML bytes."""
    return etree.tostring(
        root,
        xml_declaration=True,
        encoding="UTF-8",
        pretty_print=False
    )


class XMLBuilder:
    """
    Builds EPP XML commands.

    All methods are static and return XML bytes ready to send.
    """

    # =========================================================================
    # Session Commands
    # =========================================================================

    @staticmethod
    def build_hello() -> bytes:
        """Build hello command."""
        root = _create_epp_root()
        etree.SubElement(root, "{%s}hello" % EPP_NS)
        return _to_bytes(root)

    @staticmethod
    def build_login(
        client_id: str,
        password: str,
        new_password: str = None,
        version: str = "1.0",
        lang: str = "en",
        obj_uris: List[str] = None,
        ext_uris: List[str] = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build login command.

        Args:
            client_id: Client identifier
            password: Password
            new_password: New password (optional)
            version: EPP version
            lang: Language
            obj_uris: Object URIs to use
            ext_uris: Extension URIs to use
            cl_trid: Client transaction ID
        """
        if obj_uris is None:
            obj_uris = [DOMAIN_NS, CONTACT_NS, HOST_NS]

        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        login = etree.SubElement(command, "{%s}login" % EPP_NS)

        etree.SubElement(login, "{%s}clID" % EPP_NS).text = client_id
        etree.SubElement(login, "{%s}pw" % EPP_NS).text = password

        if new_password:
            etree.SubElement(login, "{%s}newPW" % EPP_NS).text = new_password

        options = etree.SubElement(login, "{%s}options" % EPP_NS)
        etree.SubElement(options, "{%s}version" % EPP_NS).text = version
        etree.SubElement(options, "{%s}lang" % EPP_NS).text = lang

        svcs = etree.SubElement(login, "{%s}svcs" % EPP_NS)
        for uri in obj_uris:
            etree.SubElement(svcs, "{%s}objURI" % EPP_NS).text = uri

        if ext_uris:
            svc_ext = etree.SubElement(svcs, "{%s}svcExtension" % EPP_NS)
            for uri in ext_uris:
                etree.SubElement(svc_ext, "{%s}extURI" % EPP_NS).text = uri

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_logout(cl_trid: str = None) -> bytes:
        """Build logout command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        etree.SubElement(command, "{%s}logout" % EPP_NS)
        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_poll_request(cl_trid: str = None) -> bytes:
        """Build poll request command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)

        poll = etree.SubElement(command, "{%s}poll" % EPP_NS)
        poll.set("op", "req")

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_poll_ack(msg_id: str, cl_trid: str = None) -> bytes:
        """Build poll acknowledge command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)

        poll = etree.SubElement(command, "{%s}poll" % EPP_NS)
        poll.set("op", "ack")
        poll.set("msgID", msg_id)

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # Domain Commands
    # =========================================================================

    @staticmethod
    def build_domain_check(names: List[str], cl_trid: str = None) -> bytes:
        """Build domain:check command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        check = etree.SubElement(command, "{%s}check" % EPP_NS)

        domain_check = etree.SubElement(check, "{%s}check" % DOMAIN_NS)
        for name in names:
            etree.SubElement(domain_check, "{%s}name" % DOMAIN_NS).text = name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_info(
        name: str,
        auth_info: str = None,
        hosts: str = "all",
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:info command.

        Args:
            name: Domain name
            auth_info: Auth info (for full details)
            hosts: Hosts to return - "all", "del", "sub", "none"
            cl_trid: Client transaction ID
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        info = etree.SubElement(command, "{%s}info" % EPP_NS)

        domain_info = etree.SubElement(info, "{%s}info" % DOMAIN_NS)
        name_elem = etree.SubElement(domain_info, "{%s}name" % DOMAIN_NS)
        name_elem.text = name
        name_elem.set("hosts", hosts)

        if auth_info:
            auth = etree.SubElement(domain_info, "{%s}authInfo" % DOMAIN_NS)
            etree.SubElement(auth, "{%s}pw" % DOMAIN_NS).text = auth_info

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_create(create_data: DomainCreate, cl_trid: str = None) -> bytes:
        """Build domain:create command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        create = etree.SubElement(command, "{%s}create" % EPP_NS)

        domain_create = etree.SubElement(create, "{%s}create" % DOMAIN_NS)
        etree.SubElement(domain_create, "{%s}name" % DOMAIN_NS).text = create_data.name

        period = etree.SubElement(domain_create, "{%s}period" % DOMAIN_NS)
        period.text = str(create_data.period)
        period.set("unit", create_data.period_unit)

        # Nameservers
        if create_data.nameservers:
            ns = etree.SubElement(domain_create, "{%s}ns" % DOMAIN_NS)
            for host in create_data.nameservers:
                etree.SubElement(ns, "{%s}hostObj" % DOMAIN_NS).text = host

        # Registrant
        etree.SubElement(domain_create, "{%s}registrant" % DOMAIN_NS).text = create_data.registrant

        # Contacts
        if create_data.admin:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = create_data.admin
            c.set("type", "admin")
        if create_data.tech:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = create_data.tech
            c.set("type", "tech")
        if create_data.billing:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = create_data.billing
            c.set("type", "billing")

        # Auth info
        auth_info = create_data.auth_info or _generate_auth_info()
        auth = etree.SubElement(domain_create, "{%s}authInfo" % DOMAIN_NS)
        etree.SubElement(auth, "{%s}pw" % DOMAIN_NS).text = auth_info

        _add_cl_trid(command, cl_trid)

        # Add AE Eligibility extension if present
        if create_data.ae_eligibility:
            _add_ae_eligibility_extension(command, create_data.ae_eligibility)

        return _to_bytes(root)

    @staticmethod
    def build_domain_delete(name: str, cl_trid: str = None) -> bytes:
        """Build domain:delete command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        delete = etree.SubElement(command, "{%s}delete" % EPP_NS)

        domain_delete = etree.SubElement(delete, "{%s}delete" % DOMAIN_NS)
        etree.SubElement(domain_delete, "{%s}name" % DOMAIN_NS).text = name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_renew(
        name: str,
        cur_exp_date: str,
        period: int = 1,
        period_unit: str = "y",
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:renew command.

        Args:
            name: Domain name
            cur_exp_date: Current expiry date (YYYY-MM-DD)
            period: Renewal period
            period_unit: Period unit (y=year, m=month)
            cl_trid: Client transaction ID
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        renew = etree.SubElement(command, "{%s}renew" % EPP_NS)

        domain_renew = etree.SubElement(renew, "{%s}renew" % DOMAIN_NS)
        etree.SubElement(domain_renew, "{%s}name" % DOMAIN_NS).text = name
        etree.SubElement(domain_renew, "{%s}curExpDate" % DOMAIN_NS).text = cur_exp_date

        period_elem = etree.SubElement(domain_renew, "{%s}period" % DOMAIN_NS)
        period_elem.text = str(period)
        period_elem.set("unit", period_unit)

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_transfer(
        name: str,
        op: str = "request",
        auth_info: str = None,
        period: int = None,
        period_unit: str = "y",
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:transfer command.

        Args:
            name: Domain name
            op: Operation - "request", "approve", "reject", "cancel", "query"
            auth_info: Auth info (required for request)
            period: Renewal period on transfer (optional)
            period_unit: Period unit (y=year, m=month)
            cl_trid: Client transaction ID
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        transfer = etree.SubElement(command, "{%s}transfer" % EPP_NS)
        transfer.set("op", op)

        domain_transfer = etree.SubElement(transfer, "{%s}transfer" % DOMAIN_NS)
        etree.SubElement(domain_transfer, "{%s}name" % DOMAIN_NS).text = name

        if period:
            period_elem = etree.SubElement(domain_transfer, "{%s}period" % DOMAIN_NS)
            period_elem.text = str(period)
            period_elem.set("unit", period_unit)

        if auth_info:
            auth = etree.SubElement(domain_transfer, "{%s}authInfo" % DOMAIN_NS)
            etree.SubElement(auth, "{%s}pw" % DOMAIN_NS).text = auth_info

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_update(update_data: DomainUpdate, cl_trid: str = None) -> bytes:
        """Build domain:update command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        update_cmd = etree.SubElement(command, "{%s}update" % EPP_NS)

        domain_update = etree.SubElement(update_cmd, "{%s}update" % DOMAIN_NS)
        etree.SubElement(domain_update, "{%s}name" % DOMAIN_NS).text = update_data.name

        # Add section
        if update_data.add_ns or update_data.add_contacts or update_data.add_status:
            add = etree.SubElement(domain_update, "{%s}add" % DOMAIN_NS)
            if update_data.add_ns:
                ns = etree.SubElement(add, "{%s}ns" % DOMAIN_NS)
                for host in update_data.add_ns:
                    etree.SubElement(ns, "{%s}hostObj" % DOMAIN_NS).text = host
            for contact in update_data.add_contacts:
                c = etree.SubElement(add, "{%s}contact" % DOMAIN_NS)
                c.text = contact.id
                c.set("type", contact.type)
            for status in update_data.add_status:
                s = etree.SubElement(add, "{%s}status" % DOMAIN_NS)
                if isinstance(status, StatusValue):
                    s.set("s", status.status)
                    if status.reason:
                        s.set("lang", status.lang)
                        s.text = status.reason
                else:
                    s.set("s", status)

        # Remove section
        if update_data.rem_ns or update_data.rem_contacts or update_data.rem_status:
            rem = etree.SubElement(domain_update, "{%s}rem" % DOMAIN_NS)
            if update_data.rem_ns:
                ns = etree.SubElement(rem, "{%s}ns" % DOMAIN_NS)
                for host in update_data.rem_ns:
                    etree.SubElement(ns, "{%s}hostObj" % DOMAIN_NS).text = host
            for contact in update_data.rem_contacts:
                c = etree.SubElement(rem, "{%s}contact" % DOMAIN_NS)
                c.text = contact.id
                c.set("type", contact.type)
            for status in update_data.rem_status:
                s = etree.SubElement(rem, "{%s}status" % DOMAIN_NS)
                if isinstance(status, StatusValue):
                    s.set("s", status.status)
                else:
                    s.set("s", status)

        # Change section
        if update_data.new_registrant or update_data.new_auth_info:
            chg = etree.SubElement(domain_update, "{%s}chg" % DOMAIN_NS)
            if update_data.new_registrant:
                etree.SubElement(chg, "{%s}registrant" % DOMAIN_NS).text = update_data.new_registrant
            if update_data.new_auth_info:
                auth = etree.SubElement(chg, "{%s}authInfo" % DOMAIN_NS)
                etree.SubElement(auth, "{%s}pw" % DOMAIN_NS).text = update_data.new_auth_info

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # Contact Commands
    # =========================================================================

    @staticmethod
    def build_contact_check(ids: List[str], cl_trid: str = None) -> bytes:
        """Build contact:check command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        check = etree.SubElement(command, "{%s}check" % EPP_NS)

        contact_check = etree.SubElement(check, "{%s}check" % CONTACT_NS)
        for id in ids:
            etree.SubElement(contact_check, "{%s}id" % CONTACT_NS).text = id

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_contact_info(
        id: str,
        auth_info: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """Build contact:info command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        info = etree.SubElement(command, "{%s}info" % EPP_NS)

        contact_info = etree.SubElement(info, "{%s}info" % CONTACT_NS)
        etree.SubElement(contact_info, "{%s}id" % CONTACT_NS).text = id

        if auth_info:
            auth = etree.SubElement(contact_info, "{%s}authInfo" % CONTACT_NS)
            etree.SubElement(auth, "{%s}pw" % CONTACT_NS).text = auth_info

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_contact_create(create_data: ContactCreate, cl_trid: str = None) -> bytes:
        """Build contact:create command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        create = etree.SubElement(command, "{%s}create" % EPP_NS)

        contact_create = etree.SubElement(create, "{%s}create" % CONTACT_NS)
        etree.SubElement(contact_create, "{%s}id" % CONTACT_NS).text = create_data.id

        # Postal info
        postal = etree.SubElement(contact_create, "{%s}postalInfo" % CONTACT_NS)
        postal.set("type", create_data.postal_info.type)
        etree.SubElement(postal, "{%s}name" % CONTACT_NS).text = create_data.postal_info.name
        if create_data.postal_info.org:
            etree.SubElement(postal, "{%s}org" % CONTACT_NS).text = create_data.postal_info.org
        addr = etree.SubElement(postal, "{%s}addr" % CONTACT_NS)
        for street in create_data.postal_info.street:
            etree.SubElement(addr, "{%s}street" % CONTACT_NS).text = street
        etree.SubElement(addr, "{%s}city" % CONTACT_NS).text = create_data.postal_info.city
        if create_data.postal_info.sp:
            etree.SubElement(addr, "{%s}sp" % CONTACT_NS).text = create_data.postal_info.sp
        if create_data.postal_info.pc:
            etree.SubElement(addr, "{%s}pc" % CONTACT_NS).text = create_data.postal_info.pc
        etree.SubElement(addr, "{%s}cc" % CONTACT_NS).text = create_data.postal_info.cc

        # Voice
        if create_data.voice:
            voice = etree.SubElement(contact_create, "{%s}voice" % CONTACT_NS)
            voice.text = create_data.voice
            if create_data.voice_ext:
                voice.set("x", create_data.voice_ext)

        # Fax
        if create_data.fax:
            fax = etree.SubElement(contact_create, "{%s}fax" % CONTACT_NS)
            fax.text = create_data.fax
            if create_data.fax_ext:
                fax.set("x", create_data.fax_ext)

        # Email
        etree.SubElement(contact_create, "{%s}email" % CONTACT_NS).text = create_data.email

        # Auth info
        auth_info = create_data.auth_info or _generate_auth_info()
        auth = etree.SubElement(contact_create, "{%s}authInfo" % CONTACT_NS)
        etree.SubElement(auth, "{%s}pw" % CONTACT_NS).text = auth_info

        # Disclose
        if create_data.disclose:
            disclose = etree.SubElement(contact_create, "{%s}disclose" % CONTACT_NS)
            disclose.set("flag", "1" if any(create_data.disclose.values()) else "0")
            for field, show in create_data.disclose.items():
                if show:
                    etree.SubElement(disclose, "{%s}%s" % (CONTACT_NS, field))

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_contact_delete(id: str, cl_trid: str = None) -> bytes:
        """Build contact:delete command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        delete = etree.SubElement(command, "{%s}delete" % EPP_NS)

        contact_delete = etree.SubElement(delete, "{%s}delete" % CONTACT_NS)
        etree.SubElement(contact_delete, "{%s}id" % CONTACT_NS).text = id

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_contact_update(update_data: ContactUpdate, cl_trid: str = None) -> bytes:
        """Build contact:update command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        update_cmd = etree.SubElement(command, "{%s}update" % EPP_NS)

        contact_update = etree.SubElement(update_cmd, "{%s}update" % CONTACT_NS)
        etree.SubElement(contact_update, "{%s}id" % CONTACT_NS).text = update_data.id

        # Add section
        if update_data.add_status:
            add = etree.SubElement(contact_update, "{%s}add" % CONTACT_NS)
            for status in update_data.add_status:
                s = etree.SubElement(add, "{%s}status" % CONTACT_NS)
                s.set("s", status)

        # Remove section
        if update_data.rem_status:
            rem = etree.SubElement(contact_update, "{%s}rem" % CONTACT_NS)
            for status in update_data.rem_status:
                s = etree.SubElement(rem, "{%s}status" % CONTACT_NS)
                s.set("s", status)

        # Change section
        if update_data.new_postal_info or update_data.new_voice or update_data.new_fax or update_data.new_email or update_data.new_auth_info:
            chg = etree.SubElement(contact_update, "{%s}chg" % CONTACT_NS)

            if update_data.new_postal_info:
                postal = etree.SubElement(chg, "{%s}postalInfo" % CONTACT_NS)
                postal.set("type", update_data.new_postal_info.type)
                etree.SubElement(postal, "{%s}name" % CONTACT_NS).text = update_data.new_postal_info.name
                if update_data.new_postal_info.org:
                    etree.SubElement(postal, "{%s}org" % CONTACT_NS).text = update_data.new_postal_info.org
                addr = etree.SubElement(postal, "{%s}addr" % CONTACT_NS)
                for street in update_data.new_postal_info.street:
                    etree.SubElement(addr, "{%s}street" % CONTACT_NS).text = street
                etree.SubElement(addr, "{%s}city" % CONTACT_NS).text = update_data.new_postal_info.city
                if update_data.new_postal_info.sp:
                    etree.SubElement(addr, "{%s}sp" % CONTACT_NS).text = update_data.new_postal_info.sp
                if update_data.new_postal_info.pc:
                    etree.SubElement(addr, "{%s}pc" % CONTACT_NS).text = update_data.new_postal_info.pc
                etree.SubElement(addr, "{%s}cc" % CONTACT_NS).text = update_data.new_postal_info.cc

            if update_data.new_voice:
                etree.SubElement(chg, "{%s}voice" % CONTACT_NS).text = update_data.new_voice
            if update_data.new_fax:
                etree.SubElement(chg, "{%s}fax" % CONTACT_NS).text = update_data.new_fax
            if update_data.new_email:
                etree.SubElement(chg, "{%s}email" % CONTACT_NS).text = update_data.new_email
            if update_data.new_auth_info:
                auth = etree.SubElement(chg, "{%s}authInfo" % CONTACT_NS)
                etree.SubElement(auth, "{%s}pw" % CONTACT_NS).text = update_data.new_auth_info

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_contact_transfer(
        contact_id: str,
        op: str = "request",
        auth_info: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build contact:transfer command per RFC 5733.

        Args:
            contact_id: Contact identifier
            op: Transfer operation - "request", "approve", "reject", "cancel", "query"
            auth_info: Authorization info (required for "request" operation)
            cl_trid: Client transaction ID

        Returns:
            EPP XML bytes

        Examples:
            # Request transfer
            xml = XMLBuilder.build_contact_transfer("sh8013", "request", "2fooBAR")

            # Query transfer status
            xml = XMLBuilder.build_contact_transfer("sh8013", "query")

            # Approve transfer (current registrar)
            xml = XMLBuilder.build_contact_transfer("sh8013", "approve")

            # Reject transfer (current registrar)
            xml = XMLBuilder.build_contact_transfer("sh8013", "reject")

            # Cancel transfer (requesting registrar)
            xml = XMLBuilder.build_contact_transfer("sh8013", "cancel")
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        transfer = etree.SubElement(command, "{%s}transfer" % EPP_NS)
        transfer.set("op", op)

        contact_transfer = etree.SubElement(transfer, "{%s}transfer" % CONTACT_NS)
        etree.SubElement(contact_transfer, "{%s}id" % CONTACT_NS).text = contact_id

        # Auth info is required for request, optional for others
        if auth_info:
            auth = etree.SubElement(contact_transfer, "{%s}authInfo" % CONTACT_NS)
            etree.SubElement(auth, "{%s}pw" % CONTACT_NS).text = auth_info

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # Host Commands
    # =========================================================================

    @staticmethod
    def build_host_check(names: List[str], cl_trid: str = None) -> bytes:
        """Build host:check command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        check = etree.SubElement(command, "{%s}check" % EPP_NS)

        host_check = etree.SubElement(check, "{%s}check" % HOST_NS)
        for name in names:
            etree.SubElement(host_check, "{%s}name" % HOST_NS).text = name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_host_info(name: str, cl_trid: str = None) -> bytes:
        """Build host:info command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        info = etree.SubElement(command, "{%s}info" % EPP_NS)

        host_info = etree.SubElement(info, "{%s}info" % HOST_NS)
        etree.SubElement(host_info, "{%s}name" % HOST_NS).text = name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_host_create(create_data: HostCreate, cl_trid: str = None) -> bytes:
        """Build host:create command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        create = etree.SubElement(command, "{%s}create" % EPP_NS)

        host_create = etree.SubElement(create, "{%s}create" % HOST_NS)
        etree.SubElement(host_create, "{%s}name" % HOST_NS).text = create_data.name

        for addr in create_data.addresses:
            a = etree.SubElement(host_create, "{%s}addr" % HOST_NS)
            a.text = addr.address
            a.set("ip", addr.ip_version)

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_host_delete(name: str, cl_trid: str = None) -> bytes:
        """Build host:delete command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        delete = etree.SubElement(command, "{%s}delete" % EPP_NS)

        host_delete = etree.SubElement(delete, "{%s}delete" % HOST_NS)
        etree.SubElement(host_delete, "{%s}name" % HOST_NS).text = name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_host_update(update_data: HostUpdate, cl_trid: str = None) -> bytes:
        """Build host:update command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        update_cmd = etree.SubElement(command, "{%s}update" % EPP_NS)

        host_update = etree.SubElement(update_cmd, "{%s}update" % HOST_NS)
        etree.SubElement(host_update, "{%s}name" % HOST_NS).text = update_data.name

        # Add section
        if update_data.add_addresses or update_data.add_status:
            add = etree.SubElement(host_update, "{%s}add" % HOST_NS)
            for addr in update_data.add_addresses:
                a = etree.SubElement(add, "{%s}addr" % HOST_NS)
                a.text = addr.address
                a.set("ip", addr.ip_version)
            for status in update_data.add_status:
                s = etree.SubElement(add, "{%s}status" % HOST_NS)
                s.set("s", status)

        # Remove section
        if update_data.rem_addresses or update_data.rem_status:
            rem = etree.SubElement(host_update, "{%s}rem" % HOST_NS)
            for addr in update_data.rem_addresses:
                a = etree.SubElement(rem, "{%s}addr" % HOST_NS)
                a.text = addr.address
                a.set("ip", addr.ip_version)
            for status in update_data.rem_status:
                s = etree.SubElement(rem, "{%s}status" % HOST_NS)
                s.set("s", status)

        # Change section
        if update_data.new_name:
            chg = etree.SubElement(host_update, "{%s}chg" % HOST_NS)
            etree.SubElement(chg, "{%s}name" % HOST_NS).text = update_data.new_name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # AE Extension Commands
    # =========================================================================

    @staticmethod
    def build_ae_modify_registrant(
        domain_name: str,
        registrant_name: str,
        explanation: str,
        eligibility_type: str = None,
        policy_reason: int = None,
        registrant_id: str = None,
        registrant_id_type: str = None,
        eligibility_name: str = None,
        eligibility_id: str = None,
        eligibility_id_type: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:update with aeext:update extension for ModifyRegistrant.

        This command corrects AE extension data where the legal registrant
        has NOT changed. Use to fix incorrectly specified eligibility data.

        Per aeext-1.0.xsd:
        - registrantName: Required
        - explanation: Required (max 1000 chars)
        - eligibilityType: Optional
        - policyReason: Optional (1-99)
        - registrantID + type: Optional
        - eligibilityName: Optional
        - eligibilityID + type: Optional

        Args:
            domain_name: Domain name to modify
            registrant_name: Legal name of registrant (required)
            explanation: Reason for modification (required, max 1000 chars)
            eligibility_type: Type of eligibility
            policy_reason: Policy reason (1-99)
            registrant_id: Registrant ID value
            registrant_id_type: Registrant ID type (e.g., "Trade License")
            eligibility_name: Eligibility name
            eligibility_id: Eligibility ID value
            eligibility_id_type: Eligibility ID type (e.g., "Trademark")
            cl_trid: Client transaction ID

        Returns:
            EPP XML bytes
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)

        # Standard domain:update
        update = etree.SubElement(command, "{%s}update" % EPP_NS)
        domain_update = etree.SubElement(update, "{%s}update" % DOMAIN_NS)
        etree.SubElement(domain_update, "{%s}name" % DOMAIN_NS).text = domain_name

        # AE extension for modify registrant
        extension = etree.SubElement(command, "{%s}extension" % EPP_NS)
        ae_update = etree.Element(
            "{%s}update" % AEEXT_NS,
            nsmap={"aeext": AEEXT_NS}
        )

        # aeProperties container
        ae_props = etree.SubElement(ae_update, "{%s}aeProperties" % AEEXT_NS)

        # registrantName (required)
        etree.SubElement(ae_props, "{%s}registrantName" % AEEXT_NS).text = registrant_name

        # registrantID (optional, with type attribute)
        if registrant_id and registrant_id_type:
            reg_id = etree.SubElement(ae_props, "{%s}registrantID" % AEEXT_NS)
            reg_id.text = registrant_id
            reg_id.set("type", registrant_id_type)

        # eligibilityType (optional for update)
        if eligibility_type:
            etree.SubElement(ae_props, "{%s}eligibilityType" % AEEXT_NS).text = eligibility_type

        # eligibilityName (optional)
        if eligibility_name:
            etree.SubElement(ae_props, "{%s}eligibilityName" % AEEXT_NS).text = eligibility_name

        # eligibilityID (optional, with type attribute)
        if eligibility_id and eligibility_id_type:
            elig_id = etree.SubElement(ae_props, "{%s}eligibilityID" % AEEXT_NS)
            elig_id.text = eligibility_id
            elig_id.set("type", eligibility_id_type)

        # policyReason (optional)
        if policy_reason is not None:
            etree.SubElement(ae_props, "{%s}policyReason" % AEEXT_NS).text = str(policy_reason)

        # explanation (required)
        etree.SubElement(ae_update, "{%s}explanation" % AEEXT_NS).text = explanation

        extension.append(ae_update)
        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_ae_transfer_registrant(
        domain_name: str,
        cur_exp_date: str,
        registrant_name: str,
        explanation: str,
        eligibility_type: str,
        policy_reason: int,
        period: int = 1,
        period_unit: str = "y",
        registrant_id: str = None,
        registrant_id_type: str = None,
        eligibility_name: str = None,
        eligibility_id: str = None,
        eligibility_id_type: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build aeext:command/registrantTransfer for transferring domain to new legal entity.

        This is a PROTOCOL EXTENSION command that changes legal ownership and:
        - Sets new validity period starting from transfer completion
        - Charges create fee to the requesting client

        Per aeext-1.0.xsd:
        - name: Domain name (required)
        - curExpDate: Current expiry date (required, prevents replay)
        - aeProperties: Required AE properties
        - period: Optional (new validity period)
        - explanation: Required (max 1000 chars)

        Args:
            domain_name: Domain name to transfer
            cur_exp_date: Current expiry date (YYYY-MM-DD, prevents replay)
            registrant_name: New legal registrant name (required)
            explanation: Reason for transfer (required, max 1000 chars)
            eligibility_type: Type of eligibility (required)
            policy_reason: Policy reason (1-99, required)
            period: Validity period (default 1)
            period_unit: Period unit - 'y' for years, 'm' for months
            registrant_id: Registrant ID value
            registrant_id_type: Registrant ID type (e.g., "Trade License")
            eligibility_name: Eligibility name
            eligibility_id: Eligibility ID value
            eligibility_id_type: Eligibility ID type (e.g., "Trademark")
            cl_trid: Client transaction ID

        Returns:
            EPP XML bytes
        """
        nsmap = {
            None: EPP_NS,
            "aeext": AEEXT_NS,
        }
        root = etree.Element("{%s}epp" % EPP_NS, nsmap=nsmap)
        command = etree.SubElement(root, "{%s}command" % EPP_NS)

        # aeext:command/registrantTransfer (protocol extension)
        ae_cmd = etree.SubElement(command, "{%s}command" % AEEXT_NS)
        reg_transfer = etree.SubElement(ae_cmd, "{%s}registrantTransfer" % AEEXT_NS)

        # Domain name
        etree.SubElement(reg_transfer, "{%s}name" % AEEXT_NS).text = domain_name

        # Current expiry date (required to prevent replay attacks)
        etree.SubElement(reg_transfer, "{%s}curExpDate" % AEEXT_NS).text = cur_exp_date

        # Period (optional)
        if period:
            period_elem = etree.SubElement(reg_transfer, "{%s}period" % AEEXT_NS)
            period_elem.text = str(period)
            period_elem.set("unit", period_unit)

        # aeProperties container
        ae_props = etree.SubElement(reg_transfer, "{%s}aeProperties" % AEEXT_NS)

        # registrantName (required)
        etree.SubElement(ae_props, "{%s}registrantName" % AEEXT_NS).text = registrant_name

        # registrantID (optional, with type attribute)
        if registrant_id and registrant_id_type:
            reg_id = etree.SubElement(ae_props, "{%s}registrantID" % AEEXT_NS)
            reg_id.text = registrant_id
            reg_id.set("type", registrant_id_type)

        # eligibilityType (required)
        etree.SubElement(ae_props, "{%s}eligibilityType" % AEEXT_NS).text = eligibility_type

        # eligibilityName (optional)
        if eligibility_name:
            etree.SubElement(ae_props, "{%s}eligibilityName" % AEEXT_NS).text = eligibility_name

        # eligibilityID (optional, with type attribute)
        if eligibility_id and eligibility_id_type:
            elig_id = etree.SubElement(ae_props, "{%s}eligibilityID" % AEEXT_NS)
            elig_id.text = eligibility_id
            elig_id.set("type", eligibility_id_type)

        # policyReason (required)
        etree.SubElement(ae_props, "{%s}policyReason" % AEEXT_NS).text = str(policy_reason)

        # explanation (required)
        etree.SubElement(reg_transfer, "{%s}explanation" % AEEXT_NS).text = explanation

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # AR Extension Commands
    # =========================================================================

    @staticmethod
    def build_ar_undelete(
        domain_name: str,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build arext:command/undelete to restore a deleted domain.

        This is a PROTOCOL EXTENSION command that restores a domain
        from the pending delete / redemption grace period.

        Args:
            domain_name: Domain name to restore
            cl_trid: Client transaction ID

        Returns:
            EPP XML bytes
        """
        nsmap = {
            None: EPP_NS,
            "arext": AREXT_NS,
        }
        root = etree.Element("{%s}epp" % EPP_NS, nsmap=nsmap)
        command = etree.SubElement(root, "{%s}command" % EPP_NS)

        # arext:command/undelete
        ar_cmd = etree.SubElement(command, "{%s}command" % AREXT_NS)
        undelete = etree.SubElement(ar_cmd, "{%s}undelete" % AREXT_NS)

        etree.SubElement(undelete, "{%s}name" % AREXT_NS).text = domain_name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_ar_unrenew(
        domain_name: str,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build arext:command/unrenew to cancel a pending renewal.

        This is a PROTOCOL EXTENSION command that reverts a recent
        renewal, restoring the previous expiry date.

        Args:
            domain_name: Domain name to unrenew
            cl_trid: Client transaction ID

        Returns:
            EPP XML bytes
        """
        nsmap = {
            None: EPP_NS,
            "arext": AREXT_NS,
        }
        root = etree.Element("{%s}epp" % EPP_NS, nsmap=nsmap)
        command = etree.SubElement(root, "{%s}command" % EPP_NS)

        # arext:command/unrenew
        ar_cmd = etree.SubElement(command, "{%s}command" % AREXT_NS)
        unrenew = etree.SubElement(ar_cmd, "{%s}unrenew" % AREXT_NS)

        etree.SubElement(unrenew, "{%s}name" % AREXT_NS).text = domain_name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_ar_policy_delete(
        domain_name: str,
        reason: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build arext:command/policyDelete for deleting a domain due to policy violation.

        This is a PROTOCOL EXTENSION command for registry-initiated
        or policy-based domain deletion.

        Args:
            domain_name: Domain name to delete
            reason: Reason for policy deletion
            cl_trid: Client transaction ID

        Returns:
            EPP XML bytes
        """
        nsmap = {
            None: EPP_NS,
            "arext": AREXT_NS,
        }
        root = etree.Element("{%s}epp" % EPP_NS, nsmap=nsmap)
        command = etree.SubElement(root, "{%s}command" % EPP_NS)

        # arext:command/policyDelete
        ar_cmd = etree.SubElement(command, "{%s}command" % AREXT_NS)
        policy_delete = etree.SubElement(ar_cmd, "{%s}policyDelete" % AREXT_NS)

        etree.SubElement(policy_delete, "{%s}name" % AREXT_NS).text = domain_name

        if reason:
            etree.SubElement(policy_delete, "{%s}reason" % AREXT_NS).text = reason

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # AU Extension Commands
    # =========================================================================

    @staticmethod
    def build_au_modify_registrant(
        domain_name: str,
        registrant_name: str,
        explanation: str,
        eligibility_type: str,
        policy_reason: int,
        registrant_id: str = None,
        registrant_id_type: str = None,
        eligibility_name: str = None,
        eligibility_id: str = None,
        eligibility_id_type: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:update with auext:update extension for ModifyRegistrant.

        This command corrects AU extension data where the legal registrant
        has NOT changed. Use to fix incorrectly specified eligibility data.

        Per auext-1.1.xsd:
        - registrantName: Required
        - explanation: Required (max 1000 chars)
        - eligibilityType: Required
        - policyReason: Required (1-106)
        - registrantID + type: Optional
        - eligibilityName: Optional
        - eligibilityID + type: Optional

        Args:
            domain_name: Domain name to modify
            registrant_name: Legal name of registrant (required)
            explanation: Reason for modification (required, max 1000 chars)
            eligibility_type: Type of eligibility (required)
            policy_reason: Policy reason (1-106, required)
            registrant_id: Registrant ID value
            registrant_id_type: Registrant ID type (ACN, ABN, OTHER)
            eligibility_name: Eligibility name
            eligibility_id: Eligibility ID value
            eligibility_id_type: Eligibility ID type
            cl_trid: Client transaction ID

        Returns:
            EPP XML bytes
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)

        # Standard domain:update
        update = etree.SubElement(command, "{%s}update" % EPP_NS)
        domain_update = etree.SubElement(update, "{%s}update" % DOMAIN_NS)
        etree.SubElement(domain_update, "{%s}name" % DOMAIN_NS).text = domain_name

        # AU extension for modify registrant
        extension = etree.SubElement(command, "{%s}extension" % EPP_NS)
        au_update = etree.Element(
            "{%s}update" % AUEXT_NS,
            nsmap={"auext": AUEXT_NS}
        )

        # auProperties container
        au_props = etree.SubElement(au_update, "{%s}auProperties" % AUEXT_NS)

        # registrantName (required)
        etree.SubElement(au_props, "{%s}registrantName" % AUEXT_NS).text = registrant_name

        # registrantID (optional, with type attribute)
        if registrant_id and registrant_id_type:
            reg_id = etree.SubElement(au_props, "{%s}registrantID" % AUEXT_NS)
            reg_id.text = registrant_id
            reg_id.set("type", registrant_id_type)

        # eligibilityType (required)
        etree.SubElement(au_props, "{%s}eligibilityType" % AUEXT_NS).text = eligibility_type

        # eligibilityName (optional)
        if eligibility_name:
            etree.SubElement(au_props, "{%s}eligibilityName" % AUEXT_NS).text = eligibility_name

        # eligibilityID (optional, with type attribute)
        if eligibility_id and eligibility_id_type:
            elig_id = etree.SubElement(au_props, "{%s}eligibilityID" % AUEXT_NS)
            elig_id.text = eligibility_id
            elig_id.set("type", eligibility_id_type)

        # policyReason (required)
        etree.SubElement(au_props, "{%s}policyReason" % AUEXT_NS).text = str(policy_reason)

        # explanation (required)
        etree.SubElement(au_update, "{%s}explanation" % AUEXT_NS).text = explanation

        extension.append(au_update)
        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_au_transfer_registrant(
        domain_name: str,
        cur_exp_date: str,
        registrant_name: str,
        explanation: str,
        eligibility_type: str,
        policy_reason: int,
        period: int = 1,
        period_unit: str = "y",
        registrant_id: str = None,
        registrant_id_type: str = None,
        eligibility_name: str = None,
        eligibility_id: str = None,
        eligibility_id_type: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build auext:command/registrantTransfer for transferring domain to new legal entity.

        This is a PROTOCOL EXTENSION command that changes legal ownership and:
        - Sets new validity period starting from transfer completion
        - Charges create fee to the requesting client

        Per auext-1.1.xsd:
        - name: Domain name (required)
        - curExpDate: Current expiry date (required, prevents replay)
        - auProperties: Required AU properties
        - period: Optional (new validity period)
        - explanation: Required (max 1000 chars)

        Args:
            domain_name: Domain name to transfer
            cur_exp_date: Current expiry date (YYYY-MM-DD, prevents replay)
            registrant_name: New legal registrant name (required)
            explanation: Reason for transfer (required, max 1000 chars)
            eligibility_type: Type of eligibility (required)
            policy_reason: Policy reason (1-106, required)
            period: Validity period (default 1)
            period_unit: Period unit - 'y' for years, 'm' for months
            registrant_id: Registrant ID value
            registrant_id_type: Registrant ID type (ACN, ABN, OTHER)
            eligibility_name: Eligibility name
            eligibility_id: Eligibility ID value
            eligibility_id_type: Eligibility ID type
            cl_trid: Client transaction ID

        Returns:
            EPP XML bytes
        """
        nsmap = {
            None: EPP_NS,
            "auext": AUEXT_NS,
        }
        root = etree.Element("{%s}epp" % EPP_NS, nsmap=nsmap)
        command = etree.SubElement(root, "{%s}command" % EPP_NS)

        # auext:command/registrantTransfer (protocol extension)
        au_cmd = etree.SubElement(command, "{%s}command" % AUEXT_NS)
        reg_transfer = etree.SubElement(au_cmd, "{%s}registrantTransfer" % AUEXT_NS)

        # Domain name
        etree.SubElement(reg_transfer, "{%s}name" % AUEXT_NS).text = domain_name

        # Current expiry date (required to prevent replay attacks)
        etree.SubElement(reg_transfer, "{%s}curExpDate" % AUEXT_NS).text = cur_exp_date

        # Period (optional)
        if period:
            period_elem = etree.SubElement(reg_transfer, "{%s}period" % AUEXT_NS)
            period_elem.text = str(period)
            period_elem.set("unit", period_unit)

        # auProperties container
        au_props = etree.SubElement(reg_transfer, "{%s}auProperties" % AUEXT_NS)

        # registrantName (required)
        etree.SubElement(au_props, "{%s}registrantName" % AUEXT_NS).text = registrant_name

        # registrantID (optional, with type attribute)
        if registrant_id and registrant_id_type:
            reg_id = etree.SubElement(au_props, "{%s}registrantID" % AUEXT_NS)
            reg_id.text = registrant_id
            reg_id.set("type", registrant_id_type)

        # eligibilityType (required)
        etree.SubElement(au_props, "{%s}eligibilityType" % AUEXT_NS).text = eligibility_type

        # eligibilityName (optional)
        if eligibility_name:
            etree.SubElement(au_props, "{%s}eligibilityName" % AUEXT_NS).text = eligibility_name

        # eligibilityID (optional, with type attribute)
        if eligibility_id and eligibility_id_type:
            elig_id = etree.SubElement(au_props, "{%s}eligibilityID" % AUEXT_NS)
            elig_id.text = eligibility_id
            elig_id.set("type", eligibility_id_type)

        # policyReason (required)
        etree.SubElement(au_props, "{%s}policyReason" % AUEXT_NS).text = str(policy_reason)

        # explanation (required)
        etree.SubElement(reg_transfer, "{%s}explanation" % AUEXT_NS).text = explanation

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # E.164/ENUM Extension Commands
    # =========================================================================

    @staticmethod
    def build_domain_create_with_e164(
        domain_name: str,
        registrant: str,
        naptr_records: List[Dict[str, Any]],
        period: int = 1,
        period_unit: str = "y",
        admin: str = None,
        tech: str = None,
        billing: str = None,
        nameservers: List[str] = None,
        auth_info: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:create command with e164:create extension for ENUM domains.

        Per e164epp-1.0.xsd (RFC 4114), the extension adds NAPTR records to a domain.

        Args:
            domain_name: ENUM domain name (e.g., 1.2.3.4.5.6.7.8.9.0.9.4.e164.arpa)
            registrant: Registrant contact ID
            naptr_records: List of NAPTR record dicts with keys:
                - order: unsigned short (required)
                - pref: unsigned short (required)
                - flags: single char (optional)
                - svc: service field (required)
                - regex: regular expression (optional)
                - repl: replacement domain (optional)
            period: Registration period (default 1)
            period_unit: Period unit - 'y' for years, 'm' for months
            admin: Admin contact ID
            tech: Tech contact ID
            billing: Billing contact ID
            nameservers: List of nameserver hostnames
            auth_info: Auth info password
            cl_trid: Client transaction ID

        Returns:
            XML command bytes
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        create_cmd = etree.SubElement(command, "{%s}create" % EPP_NS)

        # Domain create element
        domain_create = etree.SubElement(
            create_cmd,
            "{%s}create" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )

        etree.SubElement(domain_create, "{%s}name" % DOMAIN_NS).text = domain_name

        # Period
        period_elem = etree.SubElement(domain_create, "{%s}period" % DOMAIN_NS)
        period_elem.text = str(period)
        period_elem.set("unit", period_unit)

        # Nameservers
        if nameservers:
            ns_elem = etree.SubElement(domain_create, "{%s}ns" % DOMAIN_NS)
            for ns in nameservers:
                etree.SubElement(ns_elem, "{%s}hostObj" % DOMAIN_NS).text = ns

        # Registrant
        etree.SubElement(domain_create, "{%s}registrant" % DOMAIN_NS).text = registrant

        # Contacts
        if admin:
            contact = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            contact.text = admin
            contact.set("type", "admin")
        if tech:
            contact = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            contact.text = tech
            contact.set("type", "tech")
        if billing:
            contact = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            contact.text = billing
            contact.set("type", "billing")

        # Auth info
        auth_info = auth_info or _generate_auth_info()
        auth_elem = etree.SubElement(domain_create, "{%s}authInfo" % DOMAIN_NS)
        etree.SubElement(auth_elem, "{%s}pw" % DOMAIN_NS).text = auth_info

        # E164 extension
        extension = etree.SubElement(command, "{%s}extension" % EPP_NS)
        e164_create = etree.SubElement(
            extension,
            "{%s}create" % E164_NS,
            nsmap={"e164": E164_NS}
        )

        # Add NAPTR records
        for record in naptr_records:
            naptr = etree.SubElement(e164_create, "{%s}naptr" % E164_NS)

            # order (required)
            etree.SubElement(naptr, "{%s}order" % E164_NS).text = str(record["order"])

            # pref (required)
            etree.SubElement(naptr, "{%s}pref" % E164_NS).text = str(record["pref"])

            # flags (optional)
            if record.get("flags"):
                etree.SubElement(naptr, "{%s}flags" % E164_NS).text = record["flags"]

            # svc (required)
            etree.SubElement(naptr, "{%s}svc" % E164_NS).text = record["svc"]

            # regex (optional)
            if record.get("regex"):
                etree.SubElement(naptr, "{%s}regex" % E164_NS).text = record["regex"]

            # repl (optional)
            if record.get("repl"):
                etree.SubElement(naptr, "{%s}repl" % E164_NS).text = record["repl"]

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_update_with_e164(
        domain_name: str,
        add_naptr: List[Dict[str, Any]] = None,
        rem_naptr: List[Dict[str, Any]] = None,
        add_ns: List[str] = None,
        rem_ns: List[str] = None,
        add_status: List[str] = None,
        rem_status: List[str] = None,
        new_registrant: str = None,
        new_auth_info: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:update command with e164:update extension for ENUM domains.

        Per e164epp-1.0.xsd (RFC 4114), the extension allows adding/removing NAPTR records.

        Args:
            domain_name: ENUM domain name
            add_naptr: NAPTR records to add
            rem_naptr: NAPTR records to remove
            add_ns: Nameservers to add
            rem_ns: Nameservers to remove
            add_status: Status values to add
            rem_status: Status values to remove
            new_registrant: New registrant contact ID
            new_auth_info: New auth info password
            cl_trid: Client transaction ID

        Returns:
            XML command bytes
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        update_cmd = etree.SubElement(command, "{%s}update" % EPP_NS)

        # Domain update element
        domain_update = etree.SubElement(
            update_cmd,
            "{%s}update" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )

        etree.SubElement(domain_update, "{%s}name" % DOMAIN_NS).text = domain_name

        # Add section
        if add_ns or add_status:
            add_elem = etree.SubElement(domain_update, "{%s}add" % DOMAIN_NS)
            if add_ns:
                ns_elem = etree.SubElement(add_elem, "{%s}ns" % DOMAIN_NS)
                for ns in add_ns:
                    etree.SubElement(ns_elem, "{%s}hostObj" % DOMAIN_NS).text = ns
            if add_status:
                for status in add_status:
                    status_elem = etree.SubElement(add_elem, "{%s}status" % DOMAIN_NS)
                    status_elem.set("s", status)

        # Remove section
        if rem_ns or rem_status:
            rem_elem = etree.SubElement(domain_update, "{%s}rem" % DOMAIN_NS)
            if rem_ns:
                ns_elem = etree.SubElement(rem_elem, "{%s}ns" % DOMAIN_NS)
                for ns in rem_ns:
                    etree.SubElement(ns_elem, "{%s}hostObj" % DOMAIN_NS).text = ns
            if rem_status:
                for status in rem_status:
                    status_elem = etree.SubElement(rem_elem, "{%s}status" % DOMAIN_NS)
                    status_elem.set("s", status)

        # Change section
        if new_registrant or new_auth_info:
            chg_elem = etree.SubElement(domain_update, "{%s}chg" % DOMAIN_NS)
            if new_registrant:
                etree.SubElement(chg_elem, "{%s}registrant" % DOMAIN_NS).text = new_registrant
            if new_auth_info:
                auth_elem = etree.SubElement(chg_elem, "{%s}authInfo" % DOMAIN_NS)
                etree.SubElement(auth_elem, "{%s}pw" % DOMAIN_NS).text = new_auth_info

        # E164 extension (if adding or removing NAPTR records)
        if add_naptr or rem_naptr:
            extension = etree.SubElement(command, "{%s}extension" % EPP_NS)
            e164_update = etree.SubElement(
                extension,
                "{%s}update" % E164_NS,
                nsmap={"e164": E164_NS}
            )

            # Add NAPTR records
            if add_naptr:
                e164_add = etree.SubElement(e164_update, "{%s}add" % E164_NS)
                for record in add_naptr:
                    naptr = etree.SubElement(e164_add, "{%s}naptr" % E164_NS)
                    etree.SubElement(naptr, "{%s}order" % E164_NS).text = str(record["order"])
                    etree.SubElement(naptr, "{%s}pref" % E164_NS).text = str(record["pref"])
                    if record.get("flags"):
                        etree.SubElement(naptr, "{%s}flags" % E164_NS).text = record["flags"]
                    etree.SubElement(naptr, "{%s}svc" % E164_NS).text = record["svc"]
                    if record.get("regex"):
                        etree.SubElement(naptr, "{%s}regex" % E164_NS).text = record["regex"]
                    if record.get("repl"):
                        etree.SubElement(naptr, "{%s}repl" % E164_NS).text = record["repl"]

            # Remove NAPTR records
            if rem_naptr:
                e164_rem = etree.SubElement(e164_update, "{%s}rem" % E164_NS)
                for record in rem_naptr:
                    naptr = etree.SubElement(e164_rem, "{%s}naptr" % E164_NS)
                    etree.SubElement(naptr, "{%s}order" % E164_NS).text = str(record["order"])
                    etree.SubElement(naptr, "{%s}pref" % E164_NS).text = str(record["pref"])
                    if record.get("flags"):
                        etree.SubElement(naptr, "{%s}flags" % E164_NS).text = record["flags"]
                    etree.SubElement(naptr, "{%s}svc" % E164_NS).text = record["svc"]
                    if record.get("regex"):
                        etree.SubElement(naptr, "{%s}regex" % E164_NS).text = record["regex"]
                    if record.get("repl"):
                        etree.SubElement(naptr, "{%s}repl" % E164_NS).text = record["repl"]

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # secDNS (DNSSEC) Extension Commands
    # =========================================================================

    @staticmethod
    def build_domain_create_with_secdns(
        domain_name: str,
        registrant: str,
        ds_data: List[Dict[str, Any]] = None,
        key_data: List[Dict[str, Any]] = None,
        max_sig_life: int = None,
        period: int = 1,
        period_unit: str = "y",
        admin: str = None,
        tech: str = None,
        billing: str = None,
        nameservers: List[str] = None,
        auth_info: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:create command with secDNS:create extension.

        Args:
            domain_name: Domain name to create
            registrant: Registrant contact ID
            ds_data: List of DS record dicts with keys:
                - keyTag: int (0-65535)
                - alg: int (algorithm number)
                - digestType: int (1=SHA-1, 2=SHA-256, 4=SHA-384)
                - digest: str (hex-encoded)
                - keyData: optional dict with flags, protocol, alg, pubKey
            key_data: List of Key record dicts with keys:
                - flags: int (256=ZSK, 257=KSK)
                - protocol: int (always 3)
                - alg: int
                - pubKey: str (base64-encoded)
            max_sig_life: Maximum signature lifetime in seconds
            period: Registration period
            period_unit: Period unit ('y' or 'm')
            admin, tech, billing: Contact IDs
            nameservers: List of nameserver hostnames
            auth_info: Auth info password
            cl_trid: Client transaction ID

        Returns:
            XML command bytes
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        create_cmd = etree.SubElement(command, "{%s}create" % EPP_NS)

        # Domain create element
        domain_create = etree.SubElement(
            create_cmd,
            "{%s}create" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )

        etree.SubElement(domain_create, "{%s}name" % DOMAIN_NS).text = domain_name

        period_elem = etree.SubElement(domain_create, "{%s}period" % DOMAIN_NS)
        period_elem.text = str(period)
        period_elem.set("unit", period_unit)

        if nameservers:
            ns_elem = etree.SubElement(domain_create, "{%s}ns" % DOMAIN_NS)
            for ns in nameservers:
                etree.SubElement(ns_elem, "{%s}hostObj" % DOMAIN_NS).text = ns

        etree.SubElement(domain_create, "{%s}registrant" % DOMAIN_NS).text = registrant

        if admin:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = admin
            c.set("type", "admin")
        if tech:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = tech
            c.set("type", "tech")
        if billing:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = billing
            c.set("type", "billing")

        auth_info = auth_info or _generate_auth_info()
        auth_elem = etree.SubElement(domain_create, "{%s}authInfo" % DOMAIN_NS)
        etree.SubElement(auth_elem, "{%s}pw" % DOMAIN_NS).text = auth_info

        # secDNS extension
        if ds_data or key_data:
            extension = etree.SubElement(command, "{%s}extension" % EPP_NS)
            secdns_create = etree.SubElement(
                extension,
                "{%s}create" % SECDNS_NS,
                nsmap={"secDNS": SECDNS_NS}
            )

            if max_sig_life is not None:
                etree.SubElement(secdns_create, "{%s}maxSigLife" % SECDNS_NS).text = str(max_sig_life)

            if ds_data:
                for ds in ds_data:
                    XMLBuilder._add_secdns_ds_data(secdns_create, ds)

            if key_data:
                for key in key_data:
                    XMLBuilder._add_secdns_key_data(secdns_create, key)

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_update_secdns(
        domain_name: str,
        add_ds_data: List[Dict[str, Any]] = None,
        add_key_data: List[Dict[str, Any]] = None,
        rem_ds_data: List[Dict[str, Any]] = None,
        rem_key_data: List[Dict[str, Any]] = None,
        rem_all: bool = False,
        chg_max_sig_life: int = None,
        urgent: bool = False,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:update command with secDNS:update extension.

        Args:
            domain_name: Domain name to update
            add_ds_data: DS records to add
            add_key_data: Key records to add
            rem_ds_data: DS records to remove
            rem_key_data: Key records to remove
            rem_all: Remove all DNSSEC data
            chg_max_sig_life: Change max signature lifetime
            urgent: Request urgent processing
            cl_trid: Client transaction ID

        Returns:
            XML command bytes
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        update_cmd = etree.SubElement(command, "{%s}update" % EPP_NS)

        domain_update = etree.SubElement(
            update_cmd,
            "{%s}update" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )
        etree.SubElement(domain_update, "{%s}name" % DOMAIN_NS).text = domain_name

        # secDNS extension
        extension = etree.SubElement(command, "{%s}extension" % EPP_NS)
        secdns_update = etree.SubElement(
            extension,
            "{%s}update" % SECDNS_NS,
            nsmap={"secDNS": SECDNS_NS}
        )

        if urgent:
            secdns_update.set("urgent", "true")

        # Remove section
        if rem_all or rem_ds_data or rem_key_data:
            rem = etree.SubElement(secdns_update, "{%s}rem" % SECDNS_NS)
            if rem_all:
                etree.SubElement(rem, "{%s}all" % SECDNS_NS).text = "true"
            else:
                if rem_ds_data:
                    for ds in rem_ds_data:
                        XMLBuilder._add_secdns_ds_data(rem, ds)
                if rem_key_data:
                    for key in rem_key_data:
                        XMLBuilder._add_secdns_key_data(rem, key)

        # Add section
        if add_ds_data or add_key_data:
            add = etree.SubElement(secdns_update, "{%s}add" % SECDNS_NS)
            if add_ds_data:
                for ds in add_ds_data:
                    XMLBuilder._add_secdns_ds_data(add, ds)
            if add_key_data:
                for key in add_key_data:
                    XMLBuilder._add_secdns_key_data(add, key)

        # Change section
        if chg_max_sig_life is not None:
            chg = etree.SubElement(secdns_update, "{%s}chg" % SECDNS_NS)
            etree.SubElement(chg, "{%s}maxSigLife" % SECDNS_NS).text = str(chg_max_sig_life)

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def _add_secdns_ds_data(parent: etree._Element, ds: Dict[str, Any]) -> None:
        """Add a secDNS:dsData element to parent."""
        ds_elem = etree.SubElement(parent, "{%s}dsData" % SECDNS_NS)
        etree.SubElement(ds_elem, "{%s}keyTag" % SECDNS_NS).text = str(ds.get("keyTag", 0))
        etree.SubElement(ds_elem, "{%s}alg" % SECDNS_NS).text = str(ds.get("alg", 0))
        etree.SubElement(ds_elem, "{%s}digestType" % SECDNS_NS).text = str(ds.get("digestType", 0))
        etree.SubElement(ds_elem, "{%s}digest" % SECDNS_NS).text = ds.get("digest", "")

        if ds.get("keyData"):
            XMLBuilder._add_secdns_key_data(ds_elem, ds["keyData"])

    @staticmethod
    def _add_secdns_key_data(parent: etree._Element, key: Dict[str, Any]) -> None:
        """Add a secDNS:keyData element to parent."""
        key_elem = etree.SubElement(parent, "{%s}keyData" % SECDNS_NS)
        etree.SubElement(key_elem, "{%s}flags" % SECDNS_NS).text = str(key.get("flags", 0))
        etree.SubElement(key_elem, "{%s}protocol" % SECDNS_NS).text = str(key.get("protocol", 3))
        etree.SubElement(key_elem, "{%s}alg" % SECDNS_NS).text = str(key.get("alg", 0))
        etree.SubElement(key_elem, "{%s}pubKey" % SECDNS_NS).text = key.get("pubKey", "")

    # =========================================================================
    # IDN Extension Commands
    # =========================================================================

    @staticmethod
    def build_domain_create_with_idn(
        domain_name: str,
        registrant: str,
        user_form: str,
        language: str,
        period: int = 1,
        period_unit: str = "y",
        admin: str = None,
        tech: str = None,
        billing: str = None,
        nameservers: List[str] = None,
        auth_info: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:create command with idnadomain:create extension.

        Args:
            domain_name: Domain name (ACE/Punycode form)
            registrant: Registrant contact ID
            user_form: Unicode form of domain name
            language: BCP 47 language tag (e.g., "ar" for Arabic)
            period: Registration period
            period_unit: Period unit
            admin, tech, billing: Contact IDs
            nameservers: Nameserver list
            auth_info: Auth info
            cl_trid: Client transaction ID

        Returns:
            XML command bytes
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        create_cmd = etree.SubElement(command, "{%s}create" % EPP_NS)

        domain_create = etree.SubElement(
            create_cmd,
            "{%s}create" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )

        etree.SubElement(domain_create, "{%s}name" % DOMAIN_NS).text = domain_name

        period_elem = etree.SubElement(domain_create, "{%s}period" % DOMAIN_NS)
        period_elem.text = str(period)
        period_elem.set("unit", period_unit)

        if nameservers:
            ns_elem = etree.SubElement(domain_create, "{%s}ns" % DOMAIN_NS)
            for ns in nameservers:
                etree.SubElement(ns_elem, "{%s}hostObj" % DOMAIN_NS).text = ns

        etree.SubElement(domain_create, "{%s}registrant" % DOMAIN_NS).text = registrant

        if admin:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = admin
            c.set("type", "admin")
        if tech:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = tech
            c.set("type", "tech")
        if billing:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = billing
            c.set("type", "billing")

        auth_info = auth_info or _generate_auth_info()
        auth_elem = etree.SubElement(domain_create, "{%s}authInfo" % DOMAIN_NS)
        etree.SubElement(auth_elem, "{%s}pw" % DOMAIN_NS).text = auth_info

        # IDN extension
        extension = etree.SubElement(command, "{%s}extension" % EPP_NS)
        idn_create = etree.SubElement(
            extension,
            "{%s}create" % IDN_NS,
            nsmap={"idnadomain": IDN_NS}
        )

        user_form_elem = etree.SubElement(idn_create, "{%s}userForm" % IDN_NS)
        user_form_elem.text = user_form
        user_form_elem.set("language", language)

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # Variant Extension Commands
    # =========================================================================

    @staticmethod
    def build_domain_info_with_variant(
        domain_name: str,
        variants: str = "all",
        auth_info: str = None,
        hosts: str = "all",
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:info command with variant:info extension.

        Args:
            domain_name: Domain name to query
            variants: "all" to include variants, "none" to exclude
            auth_info: Optional auth info
            hosts: Host filtering
            cl_trid: Client transaction ID

        Returns:
            XML command bytes
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        info_cmd = etree.SubElement(command, "{%s}info" % EPP_NS)

        domain_info = etree.SubElement(
            info_cmd,
            "{%s}info" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )

        name_elem = etree.SubElement(domain_info, "{%s}name" % DOMAIN_NS)
        name_elem.text = domain_name
        name_elem.set("hosts", hosts)

        if auth_info:
            auth_elem = etree.SubElement(domain_info, "{%s}authInfo" % DOMAIN_NS)
            etree.SubElement(auth_elem, "{%s}pw" % DOMAIN_NS).text = auth_info

        # Variant extension
        extension = etree.SubElement(command, "{%s}extension" % EPP_NS)
        variant_info = etree.SubElement(
            extension,
            "{%s}info" % VARIANT_NS,
            nsmap={"variant": VARIANT_NS}
        )
        variant_info.set("variants", variants)

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_update_with_variant(
        domain_name: str,
        add_variants: List[Dict[str, str]] = None,
        rem_variants: List[Dict[str, str]] = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:update command with variant:update extension.

        Args:
            domain_name: Domain name to update
            add_variants: Variants to add [{"name": "xn--...", "userForm": "..."}]
            rem_variants: Variants to remove
            cl_trid: Client transaction ID

        Returns:
            XML command bytes
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        update_cmd = etree.SubElement(command, "{%s}update" % EPP_NS)

        domain_update = etree.SubElement(
            update_cmd,
            "{%s}update" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )
        etree.SubElement(domain_update, "{%s}name" % DOMAIN_NS).text = domain_name

        # Variant extension
        extension = etree.SubElement(command, "{%s}extension" % EPP_NS)
        variant_update = etree.SubElement(
            extension,
            "{%s}update" % VARIANT_NS,
            nsmap={"variant": VARIANT_NS}
        )

        if add_variants:
            add = etree.SubElement(variant_update, "{%s}add" % VARIANT_NS)
            for var in add_variants:
                var_elem = etree.SubElement(add, "{%s}variant" % VARIANT_NS)
                var_elem.text = var.get("name", "")
                var_elem.set("userForm", var.get("userForm", ""))

        if rem_variants:
            rem = etree.SubElement(variant_update, "{%s}rem" % VARIANT_NS)
            for var in rem_variants:
                var_elem = etree.SubElement(rem, "{%s}variant" % VARIANT_NS)
                var_elem.text = var.get("name", "")
                var_elem.set("userForm", var.get("userForm", ""))

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # Sync Extension Commands
    # =========================================================================

    @staticmethod
    def build_domain_update_with_sync(
        domain_name: str,
        exp_date: str,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:update command with sync:update extension.

        Args:
            domain_name: Domain name to update
            exp_date: New expiry date (ISO 8601 format)
            cl_trid: Client transaction ID

        Returns:
            XML command bytes
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        update_cmd = etree.SubElement(command, "{%s}update" % EPP_NS)

        domain_update = etree.SubElement(
            update_cmd,
            "{%s}update" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )
        etree.SubElement(domain_update, "{%s}name" % DOMAIN_NS).text = domain_name

        # Sync extension
        extension = etree.SubElement(command, "{%s}extension" % EPP_NS)
        sync_update = etree.SubElement(
            extension,
            "{%s}update" % SYNC_NS,
            nsmap={"sync": SYNC_NS}
        )
        etree.SubElement(sync_update, "{%s}exDate" % SYNC_NS).text = exp_date

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # KV Extension Commands
    # =========================================================================

    @staticmethod
    def build_domain_create_with_kv(
        domain_name: str,
        registrant: str,
        kvlists: List[Dict[str, Any]],
        period: int = 1,
        period_unit: str = "y",
        admin: str = None,
        tech: str = None,
        billing: str = None,
        nameservers: List[str] = None,
        auth_info: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:create command with kv:create extension.

        Args:
            domain_name: Domain name to create
            registrant: Registrant contact ID
            kvlists: List of key-value lists:
                [{"name": "list_name", "items": [{"key": "k", "value": "v"}]}]
            period: Registration period
            period_unit: Period unit
            admin, tech, billing: Contact IDs
            nameservers: Nameserver list
            auth_info: Auth info
            cl_trid: Client transaction ID

        Returns:
            XML command bytes
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        create_cmd = etree.SubElement(command, "{%s}create" % EPP_NS)

        domain_create = etree.SubElement(
            create_cmd,
            "{%s}create" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )

        etree.SubElement(domain_create, "{%s}name" % DOMAIN_NS).text = domain_name

        period_elem = etree.SubElement(domain_create, "{%s}period" % DOMAIN_NS)
        period_elem.text = str(period)
        period_elem.set("unit", period_unit)

        if nameservers:
            ns_elem = etree.SubElement(domain_create, "{%s}ns" % DOMAIN_NS)
            for ns in nameservers:
                etree.SubElement(ns_elem, "{%s}hostObj" % DOMAIN_NS).text = ns

        etree.SubElement(domain_create, "{%s}registrant" % DOMAIN_NS).text = registrant

        if admin:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = admin
            c.set("type", "admin")
        if tech:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = tech
            c.set("type", "tech")
        if billing:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = billing
            c.set("type", "billing")

        auth_info = auth_info or _generate_auth_info()
        auth_elem = etree.SubElement(domain_create, "{%s}authInfo" % DOMAIN_NS)
        etree.SubElement(auth_elem, "{%s}pw" % DOMAIN_NS).text = auth_info

        # KV extension
        extension = etree.SubElement(command, "{%s}extension" % EPP_NS)
        kv_create = etree.SubElement(
            extension,
            "{%s}create" % KV_NS,
            nsmap={"kv": KV_NS}
        )

        for kvlist in kvlists:
            list_elem = etree.SubElement(kv_create, "{%s}kvlist" % KV_NS)
            list_elem.set("name", kvlist.get("name", ""))
            for item in kvlist.get("items", []):
                item_elem = etree.SubElement(list_elem, "{%s}item" % KV_NS)
                item_elem.set("key", item.get("key", ""))
                item_elem.text = item.get("value", "")

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_update_with_kv(
        domain_name: str,
        kvlists: List[Dict[str, Any]],
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:update command with kv:update extension.

        Args:
            domain_name: Domain name to update
            kvlists: Key-value lists to set/update
            cl_trid: Client transaction ID

        Returns:
            XML command bytes
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        update_cmd = etree.SubElement(command, "{%s}update" % EPP_NS)

        domain_update = etree.SubElement(
            update_cmd,
            "{%s}update" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )
        etree.SubElement(domain_update, "{%s}name" % DOMAIN_NS).text = domain_name

        # KV extension
        extension = etree.SubElement(command, "{%s}extension" % EPP_NS)
        kv_update = etree.SubElement(
            extension,
            "{%s}update" % KV_NS,
            nsmap={"kv": KV_NS}
        )

        for kvlist in kvlists:
            list_elem = etree.SubElement(kv_update, "{%s}kvlist" % KV_NS)
            list_elem.set("name", kvlist.get("name", ""))
            for item in kvlist.get("items", []):
                item_elem = etree.SubElement(list_elem, "{%s}item" % KV_NS)
                item_elem.set("key", item.get("key", ""))
                item_elem.text = item.get("value", "")

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)
