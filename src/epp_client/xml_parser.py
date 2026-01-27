"""
EPP XML Parser

Parses EPP XML responses per RFC 5730-5733.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from lxml import etree

from epp_client.exceptions import EPPXMLError
from epp_client.models import (
    Greeting,
    EPPResponse,
    DomainCheckResult,
    DomainCheckItem,
    DomainInfo,
    DomainContact,
    DomainEligibilityInfo,
    DomainCreateResult,
    DomainRenewResult,
    DomainTransferResult,
    ContactCheckResult,
    ContactCheckItem,
    ContactInfo,
    ContactTransferResult,
    PostalInfoData,
    ContactCreateResult,
    HostCheckResult,
    HostCheckItem,
    HostInfo,
    HostAddress,
    HostCreateResult,
    PollMessage,
    AETransferRegistrantResult,
    AEPropertiesInfo,
    ARUndeleteResult,
    ARUnrenewResult,
    AUTransferRegistrantResult,
    AUPropertiesInfo,
    NAPTRRecord,
    E164InfoData,
    # Phase 7-11 extensions
    DSData,
    KeyData,
    SecDNSInfo,
    IDNData,
    DomainVariant,
    VariantInfo,
    KVItem,
    KVList,
    KVInfo,
)

logger = logging.getLogger("epp.parser")

# Namespaces
NS = {
    "epp": "urn:ietf:params:xml:ns:epp-1.0",
    "domain": "urn:ietf:params:xml:ns:domain-1.0",
    "contact": "urn:ietf:params:xml:ns:contact-1.0",
    "host": "urn:ietf:params:xml:ns:host-1.0",
    "aeEligibility": "urn:aeda:params:xml:ns:aeEligibility-1.0",
    "aeext": "urn:X-ae:params:xml:ns:aeext-1.0",
    "arext": "urn:X-ar:params:xml:ns:arext-1.0",
    "auext": "urn:X-au:params:xml:ns:auext-1.1",
    "e164": "urn:ietf:params:xml:ns:e164epp-1.0",
    # Phase 7-11 extension namespaces
    "secDNS": "urn:ietf:params:xml:ns:secDNS-1.1",
    "idnadomain": "urn:X-ar:params:xml:ns:idnadomain-1.0",
    "variant": "urn:X-ar:params:xml:ns:variant-1.0",
    "sync": "urn:X-ar:params:xml:ns:sync-1.0",
    "kv": "urn:X-ar:params:xml:ns:kv-1.0",
}

# Secure parser
_parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    remove_blank_text=True,
)


def _parse_datetime(text: str) -> Optional[datetime]:
    """Parse ISO datetime string."""
    if not text:
        return None
    try:
        text = text.replace("Z", "+00:00")
        if "." in text:
            return datetime.fromisoformat(text.split(".")[0])
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _find_text(elem: etree._Element, path: str, default: str = None) -> Optional[str]:
    """Find element and return text."""
    found = elem.find(path, NS)
    if found is not None and found.text:
        return found.text
    return default


def _find_all_text(elem: etree._Element, path: str) -> List[str]:
    """Find all elements and return their text."""
    return [e.text for e in elem.findall(path, NS) if e.text]


def _parse_xml(xml_data: bytes) -> etree._Element:
    """Parse XML with secure parser."""
    try:
        return etree.fromstring(xml_data, _parser)
    except etree.XMLSyntaxError as e:
        raise EPPXMLError(f"XML parse error: {e}")


class XMLParser:
    """
    Parses EPP XML responses.

    All methods are static and return structured response objects.
    """

    @staticmethod
    def parse_greeting(xml_data: bytes) -> Greeting:
        """
        Parse EPP greeting.

        Args:
            xml_data: Raw XML bytes

        Returns:
            Greeting object
        """
        root = _parse_xml(xml_data)

        greeting = root.find("epp:greeting", NS)
        if greeting is None:
            raise EPPXMLError("No greeting element found")

        # Parse DCP (Data Collection Policy)
        dcp = None
        dcp_elem = greeting.find("epp:dcp", NS)
        if dcp_elem is not None:
            dcp = XMLParser._parse_dcp(dcp_elem)

        return Greeting(
            server_id=_find_text(greeting, "epp:svID", ""),
            server_date=_parse_datetime(_find_text(greeting, "epp:svDate")),
            version=_find_all_text(greeting, "epp:svcMenu/epp:version"),
            lang=_find_all_text(greeting, "epp:svcMenu/epp:lang"),
            obj_uris=_find_all_text(greeting, "epp:svcMenu/epp:objURI"),
            ext_uris=_find_all_text(greeting, "epp:svcMenu/epp:svcExtension/epp:extURI"),
            dcp=dcp,
        )

    @staticmethod
    def _parse_dcp(dcp_elem) -> Dict[str, Any]:
        """
        Parse Data Collection Policy from greeting.

        Per RFC 5730, DCP contains:
        - access: How server accesses data
        - statement: One or more policy statements with:
            - purpose: Why data is collected
            - recipient: Who receives data
            - retention: How long data is kept
            - expiry: When policy expires (optional)

        Returns:
            Dict with DCP fields
        """
        dcp = {}

        # Parse access
        access_elem = dcp_elem.find("epp:access", NS)
        if access_elem is not None and len(access_elem) > 0:
            # Access type is the tag name of the first child
            dcp["access"] = access_elem[0].tag.split("}")[-1]

        # Parse statements (can be multiple)
        statements = []
        for stmt_elem in dcp_elem.findall("epp:statement", NS):
            statement = {}

            # Parse purpose (multiple values possible)
            purpose_elem = stmt_elem.find("epp:purpose", NS)
            if purpose_elem is not None:
                statement["purpose"] = [
                    child.tag.split("}")[-1] for child in purpose_elem
                ]

            # Parse recipient (multiple values possible)
            recipient_elem = stmt_elem.find("epp:recipient", NS)
            if recipient_elem is not None:
                statement["recipient"] = [
                    child.tag.split("}")[-1] for child in recipient_elem
                ]

            # Parse retention
            retention_elem = stmt_elem.find("epp:retention", NS)
            if retention_elem is not None and len(retention_elem) > 0:
                statement["retention"] = retention_elem[0].tag.split("}")[-1]

            # Parse expiry (optional)
            expiry_elem = stmt_elem.find("epp:expiry", NS)
            if expiry_elem is not None:
                abs_elem = expiry_elem.find("epp:absolute", NS)
                rel_elem = expiry_elem.find("epp:relative", NS)
                if abs_elem is not None and abs_elem.text:
                    statement["expiry"] = {"type": "absolute", "value": abs_elem.text}
                elif rel_elem is not None and rel_elem.text:
                    statement["expiry"] = {"type": "relative", "value": rel_elem.text}

            statements.append(statement)

        dcp["statements"] = statements

        return dcp

    @staticmethod
    def parse_response(xml_data: bytes) -> EPPResponse:
        """
        Parse EPP response.

        Args:
            xml_data: Raw XML bytes

        Returns:
            EPPResponse object
        """
        root = _parse_xml(xml_data)

        response = root.find("epp:response", NS)
        if response is None:
            raise EPPXMLError("No response element found")

        # Get result
        result = response.find("epp:result", NS)
        if result is None:
            raise EPPXMLError("No result element found")

        code = int(result.get("code", "2400"))
        msg = _find_text(result, "epp:msg", "Unknown error")

        # Get transaction IDs
        trn_id = response.find("epp:trID", NS)
        cl_trid = None
        sv_trid = None
        if trn_id is not None:
            cl_trid = _find_text(trn_id, "epp:clTRID")
            sv_trid = _find_text(trn_id, "epp:svTRID")

        return EPPResponse(
            code=code,
            message=msg,
            cl_trid=cl_trid,
            sv_trid=sv_trid,
            raw_xml=xml_data.decode("utf-8", errors="replace"),
        )

    @staticmethod
    def parse_domain_check(xml_data: bytes) -> DomainCheckResult:
        """Parse domain check response."""
        root = _parse_xml(xml_data)

        check_data = root.find(".//domain:chkData", NS)
        if check_data is None:
            raise EPPXMLError("No domain:chkData element found")

        results = []
        for cd in check_data.findall("domain:cd", NS):
            name_elem = cd.find("domain:name", NS)
            if name_elem is not None:
                name = name_elem.text
                avail = name_elem.get("avail", "0") in ("1", "true")
                reason = _find_text(cd, "domain:reason")
                results.append(DomainCheckItem(name=name, available=avail, reason=reason))

        return DomainCheckResult(results=results)

    @staticmethod
    def parse_domain_info(xml_data: bytes) -> DomainInfo:
        """Parse domain info response."""
        root = _parse_xml(xml_data)

        info_data = root.find(".//domain:infData", NS)
        if info_data is None:
            raise EPPXMLError("No domain:infData element found")

        # Status
        statuses = []
        for s in info_data.findall("domain:status", NS):
            statuses.append(s.get("s", ""))

        # Contacts
        contacts = []
        for c in info_data.findall("domain:contact", NS):
            contacts.append(DomainContact(
                id=c.text,
                type=c.get("type", "")
            ))

        # Nameservers
        ns = info_data.find("domain:ns", NS)
        nameservers = []
        if ns is not None:
            nameservers = _find_all_text(ns, "domain:hostObj")
            if not nameservers:
                nameservers = _find_all_text(ns, "domain:hostAttr/domain:hostName")

        # Hosts (subordinate)
        hosts = _find_all_text(info_data, "domain:host")

        # Auth info
        auth_info = _find_text(info_data, "domain:authInfo/domain:pw")

        # Parse extension data (AE eligibility)
        eligibility = XMLParser._parse_ae_eligibility_extension(root)

        return DomainInfo(
            name=_find_text(info_data, "domain:name", ""),
            roid=_find_text(info_data, "domain:roid", ""),
            status=statuses,
            registrant=_find_text(info_data, "domain:registrant"),
            contacts=contacts,
            nameservers=nameservers,
            hosts=hosts,
            cl_id=_find_text(info_data, "domain:clID", ""),
            cr_id=_find_text(info_data, "domain:crID"),
            cr_date=_parse_datetime(_find_text(info_data, "domain:crDate")),
            up_id=_find_text(info_data, "domain:upID"),
            up_date=_parse_datetime(_find_text(info_data, "domain:upDate")),
            ex_date=_parse_datetime(_find_text(info_data, "domain:exDate")),
            tr_date=_parse_datetime(_find_text(info_data, "domain:trDate")),
            auth_info=auth_info,
            eligibility=eligibility,
        )

    @staticmethod
    def _parse_ae_eligibility_extension(root: etree._Element) -> Optional[DomainEligibilityInfo]:
        """Parse AE eligibility extension from domain info response."""
        # Look for extension element
        extension = root.find(".//epp:extension", NS)
        if extension is None:
            return None

        # Look for AE eligibility info in extension
        ae_info = extension.find("aeEligibility:infData", NS)
        if ae_info is None:
            return None

        # Parse policy reason as int if present
        policy_reason_text = _find_text(ae_info, "aeEligibility:policyReason")
        policy_reason = None
        if policy_reason_text:
            try:
                policy_reason = int(policy_reason_text)
            except ValueError:
                pass

        return DomainEligibilityInfo(
            eligibility_type=_find_text(ae_info, "aeEligibility:eligibilityType"),
            eligibility_name=_find_text(ae_info, "aeEligibility:eligibilityName"),
            eligibility_id=_find_text(ae_info, "aeEligibility:eligibilityID"),
            eligibility_id_type=_find_text(ae_info, "aeEligibility:eligibilityIDType"),
            policy_reason=policy_reason,
            registrant_id=_find_text(ae_info, "aeEligibility:registrantID"),
            registrant_id_type=_find_text(ae_info, "aeEligibility:registrantIDType"),
            registrant_name=_find_text(ae_info, "aeEligibility:registrantName"),
        )

    @staticmethod
    def parse_domain_create(xml_data: bytes) -> DomainCreateResult:
        """Parse domain create response."""
        root = _parse_xml(xml_data)

        create_data = root.find(".//domain:creData", NS)
        if create_data is None:
            raise EPPXMLError("No domain:creData element found")

        return DomainCreateResult(
            name=_find_text(create_data, "domain:name", ""),
            cr_date=_parse_datetime(_find_text(create_data, "domain:crDate")),
            ex_date=_parse_datetime(_find_text(create_data, "domain:exDate")),
        )

    @staticmethod
    def parse_domain_renew(xml_data: bytes) -> DomainRenewResult:
        """Parse domain renew response."""
        root = _parse_xml(xml_data)

        renew_data = root.find(".//domain:renData", NS)
        if renew_data is None:
            raise EPPXMLError("No domain:renData element found")

        return DomainRenewResult(
            name=_find_text(renew_data, "domain:name", ""),
            ex_date=_parse_datetime(_find_text(renew_data, "domain:exDate")),
        )

    @staticmethod
    def parse_domain_transfer(xml_data: bytes) -> DomainTransferResult:
        """Parse domain transfer response."""
        root = _parse_xml(xml_data)

        trn_data = root.find(".//domain:trnData", NS)
        if trn_data is None:
            raise EPPXMLError("No domain:trnData element found")

        return DomainTransferResult(
            name=_find_text(trn_data, "domain:name", ""),
            tr_status=_find_text(trn_data, "domain:trStatus", ""),
            re_id=_find_text(trn_data, "domain:reID", ""),
            re_date=_parse_datetime(_find_text(trn_data, "domain:reDate")),
            ac_id=_find_text(trn_data, "domain:acID", ""),
            ac_date=_parse_datetime(_find_text(trn_data, "domain:acDate")),
            ex_date=_parse_datetime(_find_text(trn_data, "domain:exDate")),
        )

    @staticmethod
    def parse_contact_check(xml_data: bytes) -> ContactCheckResult:
        """Parse contact check response."""
        root = _parse_xml(xml_data)

        check_data = root.find(".//contact:chkData", NS)
        if check_data is None:
            raise EPPXMLError("No contact:chkData element found")

        results = []
        for cd in check_data.findall("contact:cd", NS):
            id_elem = cd.find("contact:id", NS)
            if id_elem is not None:
                id = id_elem.text
                avail = id_elem.get("avail", "0") in ("1", "true")
                reason = _find_text(cd, "contact:reason")
                results.append(ContactCheckItem(id=id, available=avail, reason=reason))

        return ContactCheckResult(results=results)

    @staticmethod
    def parse_contact_info(xml_data: bytes) -> ContactInfo:
        """Parse contact info response."""
        root = _parse_xml(xml_data)

        info_data = root.find(".//contact:infData", NS)
        if info_data is None:
            raise EPPXMLError("No contact:infData element found")

        # Status
        statuses = []
        for s in info_data.findall("contact:status", NS):
            statuses.append(s.get("s", ""))

        # Postal info
        postal_infos = []
        for pi in info_data.findall("contact:postalInfo", NS):
            streets = _find_all_text(pi, "contact:addr/contact:street")
            postal_infos.append(PostalInfoData(
                type=pi.get("type", "int"),
                name=_find_text(pi, "contact:name"),
                org=_find_text(pi, "contact:org"),
                street=streets,
                city=_find_text(pi, "contact:addr/contact:city"),
                sp=_find_text(pi, "contact:addr/contact:sp"),
                pc=_find_text(pi, "contact:addr/contact:pc"),
                cc=_find_text(pi, "contact:addr/contact:cc"),
            ))

        # Voice
        voice_elem = info_data.find("contact:voice", NS)
        voice = voice_elem.text if voice_elem is not None else None
        voice_ext = voice_elem.get("x") if voice_elem is not None else None

        # Fax
        fax_elem = info_data.find("contact:fax", NS)
        fax = fax_elem.text if fax_elem is not None else None
        fax_ext = fax_elem.get("x") if fax_elem is not None else None

        # Auth info
        auth_info = _find_text(info_data, "contact:authInfo/contact:pw")

        return ContactInfo(
            id=_find_text(info_data, "contact:id", ""),
            roid=_find_text(info_data, "contact:roid", ""),
            status=statuses,
            postal_info=postal_infos,
            voice=voice,
            voice_ext=voice_ext,
            fax=fax,
            fax_ext=fax_ext,
            email=_find_text(info_data, "contact:email"),
            cl_id=_find_text(info_data, "contact:clID", ""),
            cr_id=_find_text(info_data, "contact:crID"),
            cr_date=_parse_datetime(_find_text(info_data, "contact:crDate")),
            up_id=_find_text(info_data, "contact:upID"),
            up_date=_parse_datetime(_find_text(info_data, "contact:upDate")),
            tr_date=_parse_datetime(_find_text(info_data, "contact:trDate")),
            auth_info=auth_info,
        )

    @staticmethod
    def parse_contact_create(xml_data: bytes) -> ContactCreateResult:
        """Parse contact create response."""
        root = _parse_xml(xml_data)

        create_data = root.find(".//contact:creData", NS)
        if create_data is None:
            raise EPPXMLError("No contact:creData element found")

        return ContactCreateResult(
            id=_find_text(create_data, "contact:id", ""),
            cr_date=_parse_datetime(_find_text(create_data, "contact:crDate")),
        )

    @staticmethod
    def parse_contact_transfer(xml_data: bytes) -> "ContactTransferResult":
        """
        Parse contact transfer response per RFC 5733.

        Args:
            xml_data: Raw XML response bytes

        Returns:
            ContactTransferResult with transfer details

        Raises:
            EPPXMLError: If contact:trnData element not found
        """
        root = _parse_xml(xml_data)

        trn_data = root.find(".//contact:trnData", NS)
        if trn_data is None:
            raise EPPXMLError("No contact:trnData element found")

        return ContactTransferResult(
            id=_find_text(trn_data, "contact:id", ""),
            tr_status=_find_text(trn_data, "contact:trStatus", ""),
            re_id=_find_text(trn_data, "contact:reID", ""),
            re_date=_parse_datetime(_find_text(trn_data, "contact:reDate")),
            ac_id=_find_text(trn_data, "contact:acID", ""),
            ac_date=_parse_datetime(_find_text(trn_data, "contact:acDate")),
        )

    @staticmethod
    def parse_host_check(xml_data: bytes) -> HostCheckResult:
        """Parse host check response."""
        root = _parse_xml(xml_data)

        check_data = root.find(".//host:chkData", NS)
        if check_data is None:
            raise EPPXMLError("No host:chkData element found")

        results = []
        for cd in check_data.findall("host:cd", NS):
            name_elem = cd.find("host:name", NS)
            if name_elem is not None:
                name = name_elem.text
                avail = name_elem.get("avail", "0") in ("1", "true")
                reason = _find_text(cd, "host:reason")
                results.append(HostCheckItem(name=name, available=avail, reason=reason))

        return HostCheckResult(results=results)

    @staticmethod
    def parse_host_info(xml_data: bytes) -> HostInfo:
        """Parse host info response."""
        root = _parse_xml(xml_data)

        info_data = root.find(".//host:infData", NS)
        if info_data is None:
            raise EPPXMLError("No host:infData element found")

        # Status
        statuses = []
        for s in info_data.findall("host:status", NS):
            statuses.append(s.get("s", ""))

        # Addresses
        addresses = []
        for addr in info_data.findall("host:addr", NS):
            addresses.append(HostAddress(
                address=addr.text,
                ip_version=addr.get("ip", "v4")
            ))

        return HostInfo(
            name=_find_text(info_data, "host:name", ""),
            roid=_find_text(info_data, "host:roid", ""),
            status=statuses,
            addresses=addresses,
            cl_id=_find_text(info_data, "host:clID", ""),
            cr_id=_find_text(info_data, "host:crID"),
            cr_date=_parse_datetime(_find_text(info_data, "host:crDate")),
            up_id=_find_text(info_data, "host:upID"),
            up_date=_parse_datetime(_find_text(info_data, "host:upDate")),
            tr_date=_parse_datetime(_find_text(info_data, "host:trDate")),
        )

    @staticmethod
    def parse_host_create(xml_data: bytes) -> HostCreateResult:
        """Parse host create response."""
        root = _parse_xml(xml_data)

        create_data = root.find(".//host:creData", NS)
        if create_data is None:
            raise EPPXMLError("No host:creData element found")

        return HostCreateResult(
            name=_find_text(create_data, "host:name", ""),
            cr_date=_parse_datetime(_find_text(create_data, "host:crDate")),
        )

    @staticmethod
    def parse_poll_message(xml_data: bytes) -> Optional[PollMessage]:
        """Parse poll message response."""
        root = _parse_xml(xml_data)

        msg_q = root.find(".//epp:msgQ", NS)
        if msg_q is None:
            return None

        return PollMessage(
            id=msg_q.get("id", ""),
            count=int(msg_q.get("count", "0")),
            qdate=_parse_datetime(_find_text(msg_q, "epp:qDate")),
            message=_find_text(msg_q, "epp:msg", ""),
        )

    # =========================================================================
    # AE Extension Parsers
    # =========================================================================

    @staticmethod
    def parse_ae_transfer_registrant(xml_data: bytes) -> AETransferRegistrantResult:
        """
        Parse aeext:rtrnData response for registrantTransfer.

        Args:
            xml_data: Raw XML response bytes

        Returns:
            AETransferRegistrantResult with name and new expiry date

        Raises:
            EPPXMLError: If aeext:rtrnData element not found
        """
        root = _parse_xml(xml_data)

        rtrn_data = root.find(".//aeext:rtrnData", NS)
        if rtrn_data is None:
            raise EPPXMLError("No aeext:rtrnData element found")

        return AETransferRegistrantResult(
            name=_find_text(rtrn_data, "aeext:name", ""),
            ex_date=_parse_datetime(_find_text(rtrn_data, "aeext:exDate")),
        )

    @staticmethod
    def parse_ae_info_extension(xml_data: bytes) -> Optional[AEPropertiesInfo]:
        """
        Parse aeext:infData extension from domain:info response.

        Args:
            xml_data: Raw XML response bytes

        Returns:
            AEPropertiesInfo with AE extension data or None if not present
        """
        root = _parse_xml(xml_data)

        # Look for aeext:infData in extension
        inf_data = root.find(".//aeext:infData", NS)
        if inf_data is None:
            return None

        # Find aeProperties container
        ae_props = inf_data.find("aeext:aeProperties", NS)
        if ae_props is None:
            return None

        # Parse policy reason as int if present
        policy_reason_text = _find_text(ae_props, "aeext:policyReason")
        policy_reason = None
        if policy_reason_text:
            try:
                policy_reason = int(policy_reason_text)
            except ValueError:
                pass

        # Parse registrantID with type attribute
        registrant_id_elem = ae_props.find("aeext:registrantID", NS)
        registrant_id = registrant_id_elem.text if registrant_id_elem is not None else None
        registrant_id_type = registrant_id_elem.get("type") if registrant_id_elem is not None else None

        # Parse eligibilityID with type attribute
        eligibility_id_elem = ae_props.find("aeext:eligibilityID", NS)
        eligibility_id = eligibility_id_elem.text if eligibility_id_elem is not None else None
        eligibility_id_type = eligibility_id_elem.get("type") if eligibility_id_elem is not None else None

        return AEPropertiesInfo(
            registrant_name=_find_text(ae_props, "aeext:registrantName", ""),
            eligibility_type=_find_text(ae_props, "aeext:eligibilityType", ""),
            registrant_id=registrant_id,
            registrant_id_type=registrant_id_type,
            eligibility_name=_find_text(ae_props, "aeext:eligibilityName"),
            eligibility_id=eligibility_id,
            eligibility_id_type=eligibility_id_type,
            policy_reason=policy_reason,
        )

    # =========================================================================
    # AR Extension Parsers
    # =========================================================================

    @staticmethod
    def parse_ar_undelete(xml_data: bytes) -> ARUndeleteResult:
        """
        Parse arext:undeleteData response.

        Args:
            xml_data: Raw XML response bytes

        Returns:
            ARUndeleteResult with domain name

        Raises:
            EPPXMLError: If arext:undeleteData element not found
        """
        root = _parse_xml(xml_data)

        undelete_data = root.find(".//arext:undeleteData", NS)
        if undelete_data is None:
            raise EPPXMLError("No arext:undeleteData element found")

        return ARUndeleteResult(
            name=_find_text(undelete_data, "arext:name", ""),
        )

    @staticmethod
    def parse_ar_unrenew(xml_data: bytes) -> ARUnrenewResult:
        """
        Parse arext:unrenewData response.

        Args:
            xml_data: Raw XML response bytes

        Returns:
            ARUnrenewResult with domain name and reverted expiry date

        Raises:
            EPPXMLError: If arext:unrenewData element not found
        """
        root = _parse_xml(xml_data)

        unrenew_data = root.find(".//arext:unrenewData", NS)
        if unrenew_data is None:
            raise EPPXMLError("No arext:unrenewData element found")

        return ARUnrenewResult(
            name=_find_text(unrenew_data, "arext:name", ""),
            ex_date=_parse_datetime(_find_text(unrenew_data, "arext:exDate")),
        )

    # =========================================================================
    # AU Extension Parsers
    # =========================================================================

    @staticmethod
    def parse_au_transfer_registrant(xml_data: bytes) -> AUTransferRegistrantResult:
        """
        Parse auext:rtrnData response for registrantTransfer.

        Args:
            xml_data: Raw XML response bytes

        Returns:
            AUTransferRegistrantResult with name and new expiry date

        Raises:
            EPPXMLError: If auext:rtrnData element not found
        """
        root = _parse_xml(xml_data)

        rtrn_data = root.find(".//auext:rtrnData", NS)
        if rtrn_data is None:
            raise EPPXMLError("No auext:rtrnData element found")

        return AUTransferRegistrantResult(
            name=_find_text(rtrn_data, "auext:name", ""),
            ex_date=_parse_datetime(_find_text(rtrn_data, "auext:exDate")),
        )

    @staticmethod
    def parse_au_info_extension(xml_data: bytes) -> Optional[AUPropertiesInfo]:
        """
        Parse auext:infData extension from domain:info response.

        Args:
            xml_data: Raw XML response bytes

        Returns:
            AUPropertiesInfo with AU extension data or None if not present
        """
        root = _parse_xml(xml_data)

        # Look for auext:infData in extension
        inf_data = root.find(".//auext:infData", NS)
        if inf_data is None:
            return None

        # Find auProperties container
        au_props = inf_data.find("auext:auProperties", NS)
        if au_props is None:
            return None

        # Parse policy reason as int (required for AU)
        policy_reason_text = _find_text(au_props, "auext:policyReason")
        policy_reason = 1
        if policy_reason_text:
            try:
                policy_reason = int(policy_reason_text)
            except ValueError:
                pass

        # Parse registrantID with type attribute
        registrant_id_elem = au_props.find("auext:registrantID", NS)
        registrant_id = registrant_id_elem.text if registrant_id_elem is not None else None
        registrant_id_type = registrant_id_elem.get("type") if registrant_id_elem is not None else None

        # Parse eligibilityID with type attribute
        eligibility_id_elem = au_props.find("auext:eligibilityID", NS)
        eligibility_id = eligibility_id_elem.text if eligibility_id_elem is not None else None
        eligibility_id_type = eligibility_id_elem.get("type") if eligibility_id_elem is not None else None

        return AUPropertiesInfo(
            registrant_name=_find_text(au_props, "auext:registrantName", ""),
            eligibility_type=_find_text(au_props, "auext:eligibilityType", ""),
            policy_reason=policy_reason,
            registrant_id=registrant_id,
            registrant_id_type=registrant_id_type,
            eligibility_name=_find_text(au_props, "auext:eligibilityName"),
            eligibility_id=eligibility_id,
            eligibility_id_type=eligibility_id_type,
        )

    # =========================================================================
    # E.164/ENUM Extension Parsers
    # =========================================================================

    @staticmethod
    def parse_e164_info_extension(xml_data: bytes) -> Optional[E164InfoData]:
        """
        Parse e164:infData extension from domain:info response.

        Per RFC 4114 (e164epp-1.0.xsd), infData contains NAPTR records.

        Args:
            xml_data: Raw XML bytes

        Returns:
            E164InfoData with NAPTR records, or None if no extension
        """
        root = etree.fromstring(xml_data, parser=_parser)

        # Find e164:infData in extension
        inf_data = root.find(".//e164:infData", NS)
        if inf_data is None:
            return None

        naptr_records = []
        for naptr in inf_data.findall("e164:naptr", NS):
            record = XMLParser._parse_naptr_record(naptr)
            if record:
                naptr_records.append(record)

        return E164InfoData(naptr_records=naptr_records)

    @staticmethod
    def _parse_naptr_record(naptr: etree._Element) -> Optional[NAPTRRecord]:
        """
        Parse a single e164:naptr element.

        Args:
            naptr: NAPTR XML element

        Returns:
            NAPTRRecord or None if parsing fails
        """
        order_elem = naptr.find("e164:order", NS)
        pref_elem = naptr.find("e164:pref", NS)
        svc_elem = naptr.find("e164:svc", NS)

        if order_elem is None or pref_elem is None or svc_elem is None:
            return None

        return NAPTRRecord(
            order=int(order_elem.text) if order_elem.text else 0,
            pref=int(pref_elem.text) if pref_elem.text else 0,
            svc=svc_elem.text or "",
            flags=_find_text(naptr, "e164:flags"),
            regex=_find_text(naptr, "e164:regex"),
            repl=_find_text(naptr, "e164:repl"),
        )

    # =========================================================================
    # Phase 7: secDNS (DNSSEC) Extension Parsers
    # =========================================================================

    @staticmethod
    def parse_secdns_info_extension(xml_data: bytes) -> Optional[SecDNSInfo]:
        """
        Parse secDNS:infData extension from domain:info response.

        Per RFC 5910, infData contains DS and/or Key data.

        Args:
            xml_data: Raw XML bytes

        Returns:
            SecDNSInfo with DS/Key records, or None if no extension
        """
        root = _parse_xml(xml_data)

        inf_data = root.find(".//secDNS:infData", NS)
        if inf_data is None:
            return None

        ds_data_list = []
        key_data_list = []
        max_sig_life = None

        # Parse maxSigLife
        max_sig_elem = inf_data.find("secDNS:maxSigLife", NS)
        if max_sig_elem is not None and max_sig_elem.text:
            try:
                max_sig_life = int(max_sig_elem.text)
            except ValueError:
                pass

        # Parse DS data
        for ds_elem in inf_data.findall("secDNS:dsData", NS):
            ds = XMLParser._parse_secdns_ds_data(ds_elem)
            if ds:
                ds_data_list.append(ds)

        # Parse standalone Key data
        for key_elem in inf_data.findall("secDNS:keyData", NS):
            key = XMLParser._parse_secdns_key_data(key_elem)
            if key:
                key_data_list.append(key)

        return SecDNSInfo(
            ds_data=ds_data_list,
            key_data=key_data_list,
            max_sig_life=max_sig_life,
        )

    @staticmethod
    def _parse_secdns_ds_data(ds_elem: etree._Element) -> Optional[DSData]:
        """Parse a single secDNS:dsData element."""
        key_tag_elem = ds_elem.find("secDNS:keyTag", NS)
        alg_elem = ds_elem.find("secDNS:alg", NS)
        digest_type_elem = ds_elem.find("secDNS:digestType", NS)
        digest_elem = ds_elem.find("secDNS:digest", NS)

        if not all([key_tag_elem, alg_elem, digest_type_elem, digest_elem]):
            return None

        # Parse optional embedded keyData
        key_data = None
        key_data_elem = ds_elem.find("secDNS:keyData", NS)
        if key_data_elem is not None:
            key_data = XMLParser._parse_secdns_key_data(key_data_elem)

        return DSData(
            key_tag=int(key_tag_elem.text) if key_tag_elem.text else 0,
            alg=int(alg_elem.text) if alg_elem.text else 0,
            digest_type=int(digest_type_elem.text) if digest_type_elem.text else 0,
            digest=digest_elem.text or "",
            key_data=key_data,
        )

    @staticmethod
    def _parse_secdns_key_data(key_elem: etree._Element) -> Optional[KeyData]:
        """Parse a single secDNS:keyData element."""
        flags_elem = key_elem.find("secDNS:flags", NS)
        protocol_elem = key_elem.find("secDNS:protocol", NS)
        alg_elem = key_elem.find("secDNS:alg", NS)
        pub_key_elem = key_elem.find("secDNS:pubKey", NS)

        if not all([flags_elem, protocol_elem, alg_elem, pub_key_elem]):
            return None

        return KeyData(
            flags=int(flags_elem.text) if flags_elem.text else 0,
            protocol=int(protocol_elem.text) if protocol_elem.text else 3,
            alg=int(alg_elem.text) if alg_elem.text else 0,
            pub_key=pub_key_elem.text or "",
        )

    # =========================================================================
    # Phase 8: IDN Extension Parsers
    # =========================================================================

    @staticmethod
    def parse_idn_info_extension(xml_data: bytes) -> Optional[IDNData]:
        """
        Parse idnadomain:infData extension from domain:info response.

        Args:
            xml_data: Raw XML bytes

        Returns:
            IDNData with user form, language, and canonical form, or None
        """
        root = _parse_xml(xml_data)

        inf_data = root.find(".//idnadomain:infData", NS)
        if inf_data is None:
            return None

        user_form_elem = inf_data.find("idnadomain:userForm", NS)
        if user_form_elem is None:
            return None

        return IDNData(
            user_form=user_form_elem.text or "",
            language=user_form_elem.get("language", ""),
            dns_form=None,  # DNS form comes from main domain:name
            canonical_form=_find_text(inf_data, "idnadomain:canonicalForm"),
        )

    @staticmethod
    def parse_idn_create_extension(xml_data: bytes) -> Optional[IDNData]:
        """
        Parse idnadomain:creData extension from domain:create response.

        Args:
            xml_data: Raw XML bytes

        Returns:
            IDNData with canonical form from create response
        """
        root = _parse_xml(xml_data)

        cre_data = root.find(".//idnadomain:creData", NS)
        if cre_data is None:
            return None

        user_form_elem = cre_data.find("idnadomain:userForm", NS)

        return IDNData(
            user_form=user_form_elem.text if user_form_elem is not None else "",
            language=user_form_elem.get("language", "") if user_form_elem is not None else "",
            dns_form=None,
            canonical_form=_find_text(cre_data, "idnadomain:canonicalForm"),
        )

    # =========================================================================
    # Phase 9: Variant Extension Parsers
    # =========================================================================

    @staticmethod
    def parse_variant_info_extension(xml_data: bytes) -> Optional[VariantInfo]:
        """
        Parse variant:infData extension from domain:info response.

        Args:
            xml_data: Raw XML bytes

        Returns:
            VariantInfo with list of domain variants, or None
        """
        root = _parse_xml(xml_data)

        inf_data = root.find(".//variant:infData", NS)
        if inf_data is None:
            return None

        variants = []
        for var_elem in inf_data.findall("variant:variant", NS):
            user_form = var_elem.get("userForm", "")
            name = var_elem.text or ""
            variants.append(DomainVariant(name=name, user_form=user_form))

        return VariantInfo(variants=variants)

    @staticmethod
    def parse_variant_create_extension(xml_data: bytes) -> Optional[VariantInfo]:
        """
        Parse variant:creData extension from domain:create response.

        Args:
            xml_data: Raw XML bytes

        Returns:
            VariantInfo with variants created
        """
        root = _parse_xml(xml_data)

        cre_data = root.find(".//variant:creData", NS)
        if cre_data is None:
            return None

        variants = []
        for var_elem in cre_data.findall("variant:variant", NS):
            user_form = var_elem.get("userForm", "")
            name = var_elem.text or ""
            variants.append(DomainVariant(name=name, user_form=user_form))

        return VariantInfo(variants=variants)

    # =========================================================================
    # Phase 11: KV Extension Parsers
    # =========================================================================

    @staticmethod
    def parse_kv_info_extension(xml_data: bytes) -> Optional[KVInfo]:
        """
        Parse kv:infData extension from domain:info response.

        Args:
            xml_data: Raw XML bytes

        Returns:
            KVInfo with key-value lists, or None
        """
        root = _parse_xml(xml_data)

        inf_data = root.find(".//kv:infData", NS)
        if inf_data is None:
            return None

        kvlists = []
        for list_elem in inf_data.findall("kv:kvlist", NS):
            list_name = list_elem.get("name", "")
            items = []
            for item_elem in list_elem.findall("kv:item", NS):
                key = item_elem.get("key", "")
                value = item_elem.text or ""
                items.append(KVItem(key=key, value=value))
            kvlists.append(KVList(name=list_name, items=items))

        return KVInfo(kvlists=kvlists)
