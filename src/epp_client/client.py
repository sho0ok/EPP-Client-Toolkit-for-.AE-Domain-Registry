"""
EPP Client

High-level EPP client for domain registry operations.
"""

import logging
import secrets
import string
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from epp_client.connection import EPPConnection
from epp_client.exceptions import (
    EPPAuthenticationError,
    EPPCommandError,
    EPPConnectionError,
    EPPObjectExists,
    EPPObjectNotFound,
)
from epp_client.models import (
    AEEligibility,
    AEPropertiesInfo,
    AETransferRegistrantResult,
    ARUndeleteResult,
    ARUnrenewResult,
    AUPropertiesInfo,
    AUTransferRegistrantResult,
    ContactCheckResult,
    ContactCreate,
    ContactCreateResult,
    ContactInfo,
    ContactTransferResult,
    ContactUpdate,
    DomainCheckResult,
    DomainCreate,
    DomainCreateResult,
    DomainInfo,
    DomainRenewResult,
    DomainTransferResult,
    DomainUpdate,
    E164InfoData,
    EPPResponse,
    Greeting,
    HostCheckResult,
    HostCreate,
    HostCreateResult,
    HostInfo,
    HostUpdate,
    NAPTRRecord,
    PollMessage,
    StatusValue,
    # Phase 7-11 extension models
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
from epp_client.xml_builder import XMLBuilder
from epp_client.xml_parser import XMLParser

logger = logging.getLogger("epp.client")


class EPPClient:
    """
    High-level EPP client for domain registry operations.

    Provides a clean API for all EPP commands:
    - Session: login, logout, hello
    - Domain: check, info, create, delete, renew, transfer, update
    - Contact: check, info, create, delete, update
    - Host: check, info, create, delete, update
    - Poll: request, acknowledge

    Example:
        client = EPPClient(
            host="epp.registry.ae",
            port=700,
            cert_file="client.crt",
            key_file="client.key",
            ca_file="ca.crt"
        )

        with client:
            client.login("registrar1", "password123")

            # Check domain availability
            result = client.domain_check(["example.ae", "test.ae"])
            for item in result.results:
                print(f"{item.name}: {'available' if item.available else 'taken'}")

            # Create a domain
            response = client.domain_create(
                name="example.ae",
                registrant="contact123",
                admin="admin123",
                tech="tech123"
            )

            client.logout()
    """

    def __init__(
        self,
        host: str,
        port: int = 700,
        cert_file: str = None,
        key_file: str = None,
        ca_file: str = None,
        timeout: int = 30,
        verify_server: bool = True,
        client_id: str = None,
        password: str = None,
        auto_login: bool = False,
        cl_trid_prefix: str = None,
    ):
        """
        Initialize EPP client.

        Args:
            host: EPP server hostname
            port: EPP server port (default: 700)
            cert_file: Path to client certificate (PEM)
            key_file: Path to client private key (PEM)
            ca_file: Path to CA certificate(s) (PEM)
            timeout: Connection timeout in seconds
            verify_server: Whether to verify server certificate
            client_id: Client/registrar ID for auto-login
            password: Password for auto-login
            auto_login: If True, automatically login on connect
            cl_trid_prefix: Prefix for auto-generated clTRID values.
                           Defaults to client_id if set, otherwise 'EPP'.
        """
        self._connection = EPPConnection(
            host=host,
            port=port,
            cert_file=cert_file,
            key_file=key_file,
            ca_file=ca_file,
            timeout=timeout,
            verify_server=verify_server,
        )

        self._client_id = client_id
        self._password = password
        self._auto_login = auto_login
        self._cl_trid_prefix = cl_trid_prefix

        self._greeting: Optional[Greeting] = None
        self._logged_in = False
        self._cl_trid_counter = 0

    @property
    def is_connected(self) -> bool:
        """Check if connected to server."""
        return self._connection.is_connected

    @property
    def is_logged_in(self) -> bool:
        """Check if logged in."""
        return self._logged_in

    @property
    def greeting(self) -> Optional[Greeting]:
        """Get server greeting received on connect."""
        return self._greeting

    def _generate_cl_trid(self) -> str:
        """
        Generate unique client transaction ID.

        Format: PREFIX.YYYYMMDD.HHMMSS.COUNTER
        Example: MYREGISTRAR.20260206.143022.0

        Matches ARI C++ toolkit convention per RFC 5730.
        """
        prefix = self._cl_trid_prefix or self._client_id or "EPP"
        now = datetime.now()
        counter = self._cl_trid_counter % 1000
        self._cl_trid_counter += 1
        return f"{prefix}.{now:%Y%m%d}.{now:%H%M%S}.{counter}"

    def _resolve_cl_trid(self, cl_trid: Optional[str] = None) -> str:
        """Return custom cl_trid if provided, otherwise auto-generate one."""
        return cl_trid if cl_trid else self._generate_cl_trid()

    def _generate_auth_info(self, length: int = 16) -> str:
        """Generate random auth info password."""
        chars = string.ascii_letters + string.digits + "!@#$%"
        return ''.join(secrets.choice(chars) for _ in range(length))

    def _send_command(self, xml: bytes) -> bytes:
        """
        Send command and receive response.

        Args:
            xml: XML command

        Returns:
            XML response

        Raises:
            EPPConnectionError: If not connected
        """
        if not self.is_connected:
            raise EPPConnectionError("Not connected to server")

        return self._connection.send_and_receive(xml)

    def _check_response(self, response: EPPResponse) -> EPPResponse:
        """
        Check response for errors and raise appropriate exceptions.

        Args:
            response: EPP response

        Returns:
            Response if successful

        Raises:
            EPPCommandError: If command failed
            EPPObjectNotFound: If object not found
            EPPObjectExists: If object already exists
            EPPAuthenticationError: If authentication failed
        """
        if response.success:
            return response

        code = response.code
        message = response.message

        # Authentication errors
        if code in (2200, 2201, 2202):
            raise EPPAuthenticationError(message, code)

        # Object not found
        if code == 2303:
            raise EPPObjectNotFound(message, code)

        # Object exists
        if code == 2302:
            raise EPPObjectExists(message, code)

        # Generic command error
        raise EPPCommandError(message, code)

    # =========================================================================
    # Connection Management
    # =========================================================================

    def connect(self) -> Greeting:
        """
        Connect to EPP server.

        Returns:
            Server greeting

        Raises:
            EPPConnectionError: If connection fails
        """
        self._connection.connect()

        # Read greeting
        greeting_xml = self._connection.receive()
        self._greeting = XMLParser.parse_greeting(greeting_xml)

        logger.info(f"Connected to {self._greeting.server_id}")

        # Auto-login if configured
        if self._auto_login and self._client_id and self._password:
            self.login(self._client_id, self._password)

        return self._greeting

    def disconnect(self) -> None:
        """Disconnect from EPP server."""
        if self._logged_in:
            try:
                self.logout()
            except Exception as e:
                logger.warning(f"Logout failed during disconnect: {e}")

        self._connection.disconnect()
        self._greeting = None
        self._logged_in = False

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
        return False

    # =========================================================================
    # Session Commands
    # =========================================================================

    def hello(self) -> Greeting:
        """
        Send hello command and receive greeting.

        Returns:
            Server greeting

        Raises:
            EPPConnectionError: If not connected
        """
        xml = XMLBuilder.build_hello()
        response_xml = self._send_command(xml)
        return XMLParser.parse_greeting(response_xml)

    def login(
        self,
        client_id: str,
        password: str,
        new_password: str = None,
        version: str = "1.0",
        lang: str = "en",
        cl_trid: str = None,
    ) -> EPPResponse:
        """
        Login to EPP server.

        Args:
            client_id: Client/registrar ID
            password: Password
            new_password: Optional new password to set
            version: EPP version (default: 1.0)
            lang: Language (default: en)

        Returns:
            EPP response

        Raises:
            EPPAuthenticationError: If login fails
        """
        # Get object URIs from greeting
        obj_uris = []
        ext_uris = []

        if self._greeting:
            obj_uris = self._greeting.obj_uris
            ext_uris = self._greeting.ext_uris

        xml = XMLBuilder.build_login(
            client_id=client_id,
            password=password,
            new_password=new_password,
            version=version,
            lang=lang,
            obj_uris=obj_uris,
            ext_uris=ext_uris,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )

        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        self._logged_in = True
        self._client_id = client_id

        logger.info(f"Logged in as {client_id}")
        return response

    def logout(self, cl_trid: str = None) -> EPPResponse:
        """
        Logout from EPP server.

        Returns:
            EPP response

        Raises:
            EPPCommandError: If logout fails
        """
        xml = XMLBuilder.build_logout(cl_trid=self._resolve_cl_trid(cl_trid))
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._logged_in = False
        logger.info("Logged out")

        return response

    # =========================================================================
    # Poll Commands
    # =========================================================================

    def poll_request(self, cl_trid: str = None) -> Tuple[EPPResponse, Optional[PollMessage]]:
        """
        Request next poll message.

        Returns:
            Tuple of (EPPResponse, PollMessage or None if queue is empty)

        Raises:
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_poll_request(cl_trid=self._resolve_cl_trid(cl_trid))
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        # 1301 = no messages
        if response.code == 1301:
            return response, None

        self._check_response(response)
        message = XMLParser.parse_poll_message(response_xml)
        return response, message

    def poll_ack(self, msg_id: str, cl_trid: str = None) -> EPPResponse:
        """
        Acknowledge poll message.

        Args:
            msg_id: Message ID to acknowledge

        Returns:
            EPP response

        Raises:
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_poll_ack(
            msg_id=msg_id,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    # =========================================================================
    # Domain Commands
    # =========================================================================

    def domain_check(self, names: Union[str, List[str]], cl_trid: str = None) -> DomainCheckResult:
        """
        Check domain availability.

        Args:
            names: Domain name(s) to check

        Returns:
            Domain check result

        Raises:
            EPPCommandError: If command fails
        """
        if isinstance(names, str):
            names = [names]

        xml = XMLBuilder.build_domain_check(
            names=names,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_check(response_xml)

    def domain_info(
        self,
        name: str,
        auth_info: str = None,
        hosts: str = "all",
        cl_trid: str = None,
    ) -> DomainInfo:
        """
        Get domain information.

        Args:
            name: Domain name
            auth_info: Optional auth info for transfer
            hosts: Host info to return: all, del, sub, none

        Returns:
            Domain info

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_info(
            name=name,
            auth_info=auth_info,
            hosts=hosts,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_info(response_xml)

    def domain_create(
        self,
        name: str,
        registrant: str,
        period: int = 1,
        period_unit: str = "y",
        admin: str = None,
        tech: str = None,
        billing: str = None,
        nameservers: List[str] = None,
        auth_info: str = None,
        ae_eligibility: AEEligibility = None,
        cl_trid: str = None,
    ) -> DomainCreateResult:
        """
        Create a domain.

        Args:
            name: Domain name
            registrant: Registrant contact ID
            period: Registration period (default: 1)
            period_unit: Period unit - y=year, m=month (default: y)
            admin: Admin contact ID
            tech: Tech contact ID
            billing: Billing contact ID
            nameservers: List of nameserver hostnames
            auth_info: Auth info (auto-generated if not provided)
            ae_eligibility: AE eligibility extension data for restricted zones
                           (.co.ae, .gov.ae, .ac.ae, etc.)

        Returns:
            Domain create result

        Raises:
            EPPObjectExists: If domain already exists
            EPPCommandError: If command fails
        """
        if auth_info is None:
            auth_info = self._generate_auth_info()

        create_data = DomainCreate(
            name=name,
            registrant=registrant,
            period=period,
            period_unit=period_unit,
            admin=admin,
            tech=tech,
            billing=billing,
            nameservers=nameservers or [],
            auth_info=auth_info,
            ae_eligibility=ae_eligibility,
        )

        xml = XMLBuilder.build_domain_create(
            create_data=create_data,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_create(response_xml)

    def domain_delete(self, name: str, cl_trid: str = None) -> EPPResponse:
        """
        Delete a domain.

        Args:
            name: Domain name

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_delete(
            name=name,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def domain_renew(
        self,
        name: str,
        cur_exp_date: str,
        period: int = 1,
        period_unit: str = "y",
        cl_trid: str = None,
    ) -> DomainRenewResult:
        """
        Renew a domain.

        Args:
            name: Domain name
            cur_exp_date: Current expiry date (YYYY-MM-DD)
            period: Renewal period (default: 1)
            period_unit: Period unit - y=year, m=month (default: y)

        Returns:
            Domain renew result

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_renew(
            name=name,
            cur_exp_date=cur_exp_date,
            period=period,
            period_unit=period_unit,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_renew(response_xml)

    def domain_transfer_request(
        self,
        name: str,
        auth_info: str,
        period: int = None,
        period_unit: str = "y",
        cl_trid: str = None,
    ) -> DomainTransferResult:
        """
        Request domain transfer.

        Args:
            name: Domain name
            auth_info: Domain auth info
            period: Optional renewal period
            period_unit: Period unit - y=year, m=month (default: y)

        Returns:
            Domain transfer result

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_transfer(
            name=name,
            op="request",
            auth_info=auth_info,
            period=period,
            period_unit=period_unit,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_transfer(response_xml)

    def domain_transfer_query(self, name: str, cl_trid: str = None) -> DomainTransferResult:
        """
        Query domain transfer status.

        Args:
            name: Domain name

        Returns:
            Domain transfer result

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_transfer(
            name=name,
            op="query",
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_transfer(response_xml)

    def domain_transfer_approve(self, name: str, cl_trid: str = None) -> EPPResponse:
        """
        Approve domain transfer.

        Args:
            name: Domain name

        Returns:
            EPP response

        Raises:
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_transfer(
            name=name,
            op="approve",
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def domain_transfer_reject(self, name: str, cl_trid: str = None) -> EPPResponse:
        """
        Reject domain transfer.

        Args:
            name: Domain name

        Returns:
            EPP response

        Raises:
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_transfer(
            name=name,
            op="reject",
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def domain_transfer_cancel(self, name: str, cl_trid: str = None) -> EPPResponse:
        """
        Cancel domain transfer request.

        Args:
            name: Domain name

        Returns:
            EPP response

        Raises:
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_transfer(
            name=name,
            op="cancel",
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def domain_update(
        self,
        name: str,
        add_ns: List[str] = None,
        rem_ns: List[str] = None,
        add_status: List = None,
        rem_status: List = None,
        new_registrant: str = None,
        new_auth_info: str = None,
        cl_trid: str = None,
    ) -> EPPResponse:
        """
        Update a domain.

        Args:
            name: Domain name
            add_ns: Nameservers to add
            rem_ns: Nameservers to remove
            add_status: Status values to add. Can be strings or StatusValue objects.
                       Example: ["clientHold"] or [StatusValue("clientHold", "Payment pending")]
            rem_status: Status values to remove. Can be strings or StatusValue objects.
            new_registrant: New registrant contact ID
            new_auth_info: New auth info

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        update_data = DomainUpdate(
            name=name,
            add_ns=add_ns or [],
            rem_ns=rem_ns or [],
            add_status=add_status or [],
            rem_status=rem_status or [],
            new_registrant=new_registrant,
            new_auth_info=new_auth_info,
        )

        xml = XMLBuilder.build_domain_update(
            update_data=update_data,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    # =========================================================================
    # Contact Commands
    # =========================================================================

    def contact_check(self, ids: Union[str, List[str]], cl_trid: str = None) -> ContactCheckResult:
        """
        Check contact availability.

        Args:
            ids: Contact ID(s) to check

        Returns:
            Contact check result

        Raises:
            EPPCommandError: If command fails
        """
        if isinstance(ids, str):
            ids = [ids]

        xml = XMLBuilder.build_contact_check(
            ids=ids,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_contact_check(response_xml)

    def contact_info(self, id: str, auth_info: str = None, cl_trid: str = None) -> ContactInfo:
        """
        Get contact information.

        Args:
            id: Contact ID
            auth_info: Optional auth info

        Returns:
            Contact info

        Raises:
            EPPObjectNotFound: If contact not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_contact_info(
            id=id,
            auth_info=auth_info,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_contact_info(response_xml)

    def contact_create(
        self,
        id: str,
        name: str,
        email: str,
        city: str,
        country_code: str,
        org: str = None,
        street: List[str] = None,
        state: str = None,
        postal_code: str = None,
        voice: str = None,
        fax: str = None,
        auth_info: str = None,
        postal_type: str = "int",
        cl_trid: str = None,
    ) -> ContactCreateResult:
        """
        Create a contact.

        Args:
            id: Contact ID
            name: Contact name
            email: Email address
            city: City
            country_code: 2-letter country code
            org: Organization name
            street: Street address lines
            state: State/province
            postal_code: Postal/ZIP code
            voice: Phone number
            fax: Fax number
            auth_info: Auth info (auto-generated if not provided)
            postal_type: Postal info type - int or loc (default: int)

        Returns:
            Contact create result

        Raises:
            EPPObjectExists: If contact already exists
            EPPCommandError: If command fails
        """
        from epp_client.models import PostalInfo

        if auth_info is None:
            auth_info = self._generate_auth_info()

        postal_info = PostalInfo(
            name=name,
            city=city,
            cc=country_code,
            type=postal_type,
            org=org,
            street=street or [],
            sp=state,
            pc=postal_code,
        )

        create_data = ContactCreate(
            id=id,
            email=email,
            postal_info=postal_info,
            voice=voice,
            fax=fax,
            auth_info=auth_info,
        )

        xml = XMLBuilder.build_contact_create(
            create_data=create_data,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_contact_create(response_xml)

    def contact_delete(self, id: str, cl_trid: str = None) -> EPPResponse:
        """
        Delete a contact.

        Args:
            id: Contact ID

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If contact not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_contact_delete(
            id=id,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def contact_update(
        self,
        id: str,
        add_status: List[str] = None,
        rem_status: List[str] = None,
        new_email: str = None,
        new_voice: str = None,
        new_fax: str = None,
        new_auth_info: str = None,
        cl_trid: str = None,
    ) -> EPPResponse:
        """
        Update a contact.

        Args:
            id: Contact ID
            add_status: Status values to add
            rem_status: Status values to remove
            new_email: New email address
            new_voice: New phone number
            new_fax: New fax number
            new_auth_info: New auth info

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If contact not found
            EPPCommandError: If command fails
        """
        update_data = ContactUpdate(
            id=id,
            add_status=add_status or [],
            rem_status=rem_status or [],
            new_email=new_email,
            new_voice=new_voice,
            new_fax=new_fax,
            new_auth_info=new_auth_info,
        )

        xml = XMLBuilder.build_contact_update(
            update_data=update_data,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def contact_transfer(
        self,
        contact_id: str,
        op: str = "request",
        auth_info: str = None,
        cl_trid: str = None,
    ) -> "ContactTransferResult":
        """
        Transfer a contact between registrars.

        Per RFC 5733, contact transfer supports five operations:
        - request: Request transfer to new registrar (requires auth_info)
        - approve: Approve incoming transfer (current registrar)
        - reject: Reject incoming transfer (current registrar)
        - cancel: Cancel outgoing transfer (requesting registrar)
        - query: Query transfer status

        Args:
            contact_id: Contact identifier
            op: Transfer operation (request/approve/reject/cancel/query)
            auth_info: Authorization info (required for request)

        Returns:
            ContactTransferResult with transfer details

        Raises:
            EPPObjectNotFound: If contact not found
            EPPAuthError: If auth info is invalid (request only)
            EPPObjectPendingTransfer: If contact has pending transfer (request)
            EPPObjectNotPendingTransfer: If no pending transfer (approve/reject/cancel)
            EPPCommandError: If command fails

        Examples:
            # Request transfer
            result = client.contact_transfer("sh8013", "request", "2fooBAR")
            print(f"Status: {result.tr_status}")  # "pending"

            # Query transfer status
            result = client.contact_transfer("sh8013", "query")

            # Approve transfer (must be current registrar)
            result = client.contact_transfer("sh8013", "approve")

            # Reject transfer (must be current registrar)
            result = client.contact_transfer("sh8013", "reject")

            # Cancel transfer (must be requesting registrar)
            result = client.contact_transfer("sh8013", "cancel")
        """
        xml = XMLBuilder.build_contact_transfer(
            contact_id=contact_id,
            op=op,
            auth_info=auth_info,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_contact_transfer(response_xml)

    # =========================================================================
    # Host Commands
    # =========================================================================

    def host_check(self, names: Union[str, List[str]], cl_trid: str = None) -> HostCheckResult:
        """
        Check host availability.

        Args:
            names: Host name(s) to check

        Returns:
            Host check result

        Raises:
            EPPCommandError: If command fails
        """
        if isinstance(names, str):
            names = [names]

        xml = XMLBuilder.build_host_check(
            names=names,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_host_check(response_xml)

    def host_info(self, name: str, cl_trid: str = None) -> HostInfo:
        """
        Get host information.

        Args:
            name: Host name

        Returns:
            Host info

        Raises:
            EPPObjectNotFound: If host not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_host_info(
            name=name,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_host_info(response_xml)

    def host_create(
        self,
        name: str,
        ipv4: List[str] = None,
        ipv6: List[str] = None,
        cl_trid: str = None,
    ) -> HostCreateResult:
        """
        Create a host.

        Args:
            name: Host name
            ipv4: List of IPv4 addresses
            ipv6: List of IPv6 addresses

        Returns:
            Host create result

        Raises:
            EPPObjectExists: If host already exists
            EPPCommandError: If command fails
        """
        from epp_client.models import HostAddress

        addresses = []
        for ip in (ipv4 or []):
            addresses.append(HostAddress(address=ip, ip_version="v4"))
        for ip in (ipv6 or []):
            addresses.append(HostAddress(address=ip, ip_version="v6"))

        create_data = HostCreate(
            name=name,
            addresses=addresses,
        )

        xml = XMLBuilder.build_host_create(
            create_data=create_data,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_host_create(response_xml)

    def host_delete(self, name: str, cl_trid: str = None) -> EPPResponse:
        """
        Delete a host.

        Args:
            name: Host name

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If host not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_host_delete(
            name=name,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def host_update(
        self,
        name: str,
        add_ipv4: List[str] = None,
        add_ipv6: List[str] = None,
        rem_ipv4: List[str] = None,
        rem_ipv6: List[str] = None,
        add_status: List[str] = None,
        rem_status: List[str] = None,
        new_name: str = None,
        cl_trid: str = None,
    ) -> EPPResponse:
        """
        Update a host.

        Args:
            name: Host name
            add_ipv4: IPv4 addresses to add
            add_ipv6: IPv6 addresses to add
            rem_ipv4: IPv4 addresses to remove
            rem_ipv6: IPv6 addresses to remove
            add_status: Status values to add
            rem_status: Status values to remove
            new_name: New host name

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If host not found
            EPPCommandError: If command fails
        """
        from epp_client.models import HostAddress

        add_addresses = []
        for ip in (add_ipv4 or []):
            add_addresses.append(HostAddress(address=ip, ip_version="v4"))
        for ip in (add_ipv6 or []):
            add_addresses.append(HostAddress(address=ip, ip_version="v6"))

        rem_addresses = []
        for ip in (rem_ipv4 or []):
            rem_addresses.append(HostAddress(address=ip, ip_version="v4"))
        for ip in (rem_ipv6 or []):
            rem_addresses.append(HostAddress(address=ip, ip_version="v6"))

        update_data = HostUpdate(
            name=name,
            add_addresses=add_addresses,
            rem_addresses=rem_addresses,
            add_status=add_status or [],
            rem_status=rem_status or [],
            new_name=new_name,
        )

        xml = XMLBuilder.build_host_update(
            update_data=update_data,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    # =========================================================================
    # AE Extension Commands
    # =========================================================================

    def ae_modify_registrant(
        self,
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
    ) -> EPPResponse:
        """
        Modify AE extension registrant data for a .ae domain.

        This command corrects eligibility data where the legal registrant
        has NOT changed. Use to fix incorrectly specified eligibility data.

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

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If domain not found
            EPPAuthorizationError: If not sponsoring registrar
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_ae_modify_registrant(
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
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def ae_transfer_registrant(
        self,
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
    ) -> AETransferRegistrantResult:
        """
        Transfer .ae domain to a new legal registrant entity.

        This is a PROTOCOL EXTENSION command that changes legal ownership:
        - Sets new validity period starting from transfer completion
        - Charges create fee to the requesting client

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
            registrant_id_type: Registrant ID type
            eligibility_name: Eligibility name
            eligibility_id: Eligibility ID value
            eligibility_id_type: Eligibility ID type

        Returns:
            AETransferRegistrantResult with domain name and new expiry date

        Raises:
            EPPObjectNotFound: If domain not found
            EPPAuthorizationError: If not sponsoring registrar
            EPPBillingError: If insufficient balance
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_ae_transfer_registrant(
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
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_ae_transfer_registrant(response_xml)

    # =========================================================================
    # AR Extension Commands
    # =========================================================================

    def ar_undelete(self, domain_name: str, cl_trid: str = None) -> ARUndeleteResult:
        """
        Restore a deleted domain from redemption grace period.

        This is a PROTOCOL EXTENSION command that restores a domain
        that is in pending delete / redemption status.

        Args:
            domain_name: Domain name to restore

        Returns:
            ARUndeleteResult with domain name

        Raises:
            EPPObjectNotFound: If domain not found
            EPPAuthorizationError: If not sponsoring registrar
            EPPCommandError: If command fails or domain not restorable
        """
        xml = XMLBuilder.build_ar_undelete(
            domain_name=domain_name,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_ar_undelete(response_xml)

    def ar_unrenew(self, domain_name: str, cl_trid: str = None) -> ARUnrenewResult:
        """
        Cancel a pending domain renewal.

        This is a PROTOCOL EXTENSION command that reverts a recent
        renewal, restoring the previous expiry date.

        Args:
            domain_name: Domain name to unrenew

        Returns:
            ARUnrenewResult with domain name and reverted expiry date

        Raises:
            EPPObjectNotFound: If domain not found
            EPPAuthorizationError: If not sponsoring registrar
            EPPCommandError: If command fails or renewal not reversible
        """
        xml = XMLBuilder.build_ar_unrenew(
            domain_name=domain_name,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_ar_unrenew(response_xml)

    def ar_policy_delete(
        self,
        domain_name: str,
        reason: str = None,
        cl_trid: str = None,
    ) -> EPPResponse:
        """
        Delete a domain due to policy violation.

        This is a PROTOCOL EXTENSION command for registry-initiated
        or policy-based domain deletion.

        Args:
            domain_name: Domain name to delete
            reason: Reason for policy deletion

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_ar_policy_delete(
            domain_name=domain_name,
            reason=reason,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    # =========================================================================
    # AU Extension Commands
    # =========================================================================

    def au_modify_registrant(
        self,
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
    ) -> EPPResponse:
        """
        Modify AU extension registrant data for a .au domain.

        This command corrects eligibility data where the legal registrant
        has NOT changed. Use to fix incorrectly specified eligibility data.

        Args:
            domain_name: Domain name to modify
            registrant_name: Legal name of registrant (required)
            explanation: Reason for modification (required, max 1000 chars)
            eligibility_type: Type of eligibility (required, e.g., "Company")
            policy_reason: Policy reason (1-106, required)
            registrant_id: Registrant ID value (e.g., ACN)
            registrant_id_type: Registrant ID type (ACN, ABN, OTHER)
            eligibility_name: Eligibility name
            eligibility_id: Eligibility ID value
            eligibility_id_type: Eligibility ID type (ACN, ABN, TM, etc.)

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If domain not found
            EPPAuthorizationError: If not sponsoring registrar
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_au_modify_registrant(
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
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def au_transfer_registrant(
        self,
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
    ) -> AUTransferRegistrantResult:
        """
        Transfer .au domain to a new legal registrant entity.

        This is a PROTOCOL EXTENSION command that changes legal ownership:
        - Sets new validity period starting from transfer completion
        - Charges create fee to the requesting client

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

        Returns:
            AUTransferRegistrantResult with domain name and new expiry date

        Raises:
            EPPObjectNotFound: If domain not found
            EPPAuthorizationError: If not sponsoring registrar
            EPPBillingError: If insufficient balance
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_au_transfer_registrant(
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
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_au_transfer_registrant(response_xml)

    # =========================================================================
    # E.164/ENUM Extension Commands
    # =========================================================================

    def enum_domain_create(
        self,
        name: str,
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
    ) -> DomainCreateResult:
        """
        Create an ENUM domain with NAPTR records.

        ENUM (E.164 NUmber Mapping) domains map telephone numbers to
        internet services via NAPTR DNS records.

        Args:
            name: ENUM domain name (e.g., 1.2.3.4.5.6.7.8.9.0.9.4.e164.arpa)
            registrant: Registrant contact ID
            naptr_records: List of NAPTR record dicts with keys:
                - order: int (required) - lower values processed first
                - pref: int (required) - preference, breaks ties
                - flags: str (optional) - single char, e.g., 'u' for terminal
                - svc: str (required) - service, e.g., 'E2U+sip'
                - regex: str (optional) - URI transformation regex
                - repl: str (optional) - replacement domain
            period: Registration period (default 1)
            period_unit: Period unit - 'y' for years, 'm' for months
            admin: Admin contact ID
            tech: Tech contact ID
            billing: Billing contact ID
            nameservers: List of nameserver hostnames
            auth_info: Auth info (auto-generated if not provided)

        Returns:
            DomainCreateResult

        Raises:
            EPPObjectExists: If domain already exists
            EPPCommandError: If command fails

        Example:
            # Create ENUM domain with SIP and email NAPTR records
            result = client.enum_domain_create(
                name="1.2.3.4.5.6.7.8.9.0.9.4.e164.arpa",
                registrant="contact123",
                naptr_records=[
                    {"order": 100, "pref": 10, "flags": "u",
                     "svc": "E2U+sip", "regex": "!^.*$!sip:user@example.com!"},
                    {"order": 100, "pref": 20, "flags": "u",
                     "svc": "E2U+mailto", "regex": "!^.*$!mailto:user@example.com!"},
                ]
            )
        """
        if auth_info is None:
            auth_info = self._generate_auth_info()

        xml = XMLBuilder.build_domain_create_with_e164(
            domain_name=name,
            registrant=registrant,
            naptr_records=naptr_records,
            period=period,
            period_unit=period_unit,
            admin=admin,
            tech=tech,
            billing=billing,
            nameservers=nameservers or [],
            auth_info=auth_info,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_create(response_xml)

    def enum_domain_update(
        self,
        name: str,
        add_naptr: List[Dict[str, Any]] = None,
        rem_naptr: List[Dict[str, Any]] = None,
        add_ns: List[str] = None,
        rem_ns: List[str] = None,
        add_status: List[str] = None,
        rem_status: List[str] = None,
        new_registrant: str = None,
        new_auth_info: str = None,
        cl_trid: str = None,
    ) -> EPPResponse:
        """
        Update an ENUM domain with NAPTR record changes.

        Args:
            name: ENUM domain name
            add_naptr: NAPTR records to add
            rem_naptr: NAPTR records to remove
            add_ns: Nameservers to add
            rem_ns: Nameservers to remove
            add_status: Status values to add
            rem_status: Status values to remove
            new_registrant: New registrant contact ID
            new_auth_info: New auth info password

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails

        Example:
            # Add a new SIP NAPTR record
            client.enum_domain_update(
                name="1.2.3.4.5.6.7.8.9.0.9.4.e164.arpa",
                add_naptr=[
                    {"order": 100, "pref": 5, "flags": "u",
                     "svc": "E2U+sip", "regex": "!^.*$!sip:new@example.com!"}
                ]
            )
        """
        xml = XMLBuilder.build_domain_update_with_e164(
            domain_name=name,
            add_naptr=add_naptr,
            rem_naptr=rem_naptr,
            add_ns=add_ns,
            rem_ns=rem_ns,
            add_status=add_status,
            rem_status=rem_status,
            new_registrant=new_registrant,
            new_auth_info=new_auth_info,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def enum_domain_info(
        self,
        name: str,
        auth_info: str = None,
        hosts: str = "all",
        cl_trid: str = None,
    ) -> Tuple[DomainInfo, Optional[E164InfoData]]:
        """
        Get ENUM domain information including NAPTR records.

        Args:
            name: ENUM domain name
            auth_info: Optional auth info for transfer query
            hosts: Host info to return: all, del, sub, none

        Returns:
            Tuple of (DomainInfo, E164InfoData or None)

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails

        Example:
            domain_info, e164_info = client.enum_domain_info(
                "1.2.3.4.5.6.7.8.9.0.9.4.e164.arpa"
            )
            if e164_info:
                for record in e164_info.naptr_records:
                    print(f"Order: {record.order}, Service: {record.svc}")
        """
        xml = XMLBuilder.build_domain_info(
            name=name,
            auth_info=auth_info,
            hosts=hosts,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)

        domain_info = XMLParser.parse_domain_info(response_xml)
        e164_info = XMLParser.parse_e164_info_extension(response_xml)

        return domain_info, e164_info

    # =========================================================================
    # Phase 7: secDNS (DNSSEC) Extension Commands
    # =========================================================================

    def domain_create_with_secdns(
        self,
        name: str,
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
    ) -> DomainCreateResult:
        """
        Create a domain with DNSSEC data.

        Args:
            name: Domain name
            registrant: Registrant contact ID
            ds_data: List of DS records, each dict with keys:
                - key_tag: int (0-65535)
                - alg: int (algorithm number)
                - digest_type: int (1=SHA-1, 2=SHA-256, 4=SHA-384)
                - digest: str (hex-encoded digest)
                - key_data: optional dict with flags, protocol, alg, pub_key
            key_data: List of Key records, each dict with keys:
                - flags: int (256=ZSK, 257=KSK)
                - protocol: int (always 3)
                - alg: int (algorithm number)
                - pub_key: str (base64-encoded public key)
            max_sig_life: Maximum signature lifetime in seconds
            period: Registration period (default 1)
            period_unit: Period unit - 'y' or 'm' (default: y)
            admin: Admin contact ID
            tech: Tech contact ID
            billing: Billing contact ID
            nameservers: List of nameserver hostnames
            auth_info: Auth info (auto-generated if not provided)

        Returns:
            DomainCreateResult

        Raises:
            EPPObjectExists: If domain already exists
            EPPCommandError: If command fails
        """
        if auth_info is None:
            auth_info = self._generate_auth_info()

        xml = XMLBuilder.build_domain_create_with_secdns(
            domain_name=name,
            registrant=registrant,
            ds_data=ds_data,
            key_data=key_data,
            max_sig_life=max_sig_life,
            period=period,
            period_unit=period_unit,
            admin=admin,
            tech=tech,
            billing=billing,
            nameservers=nameservers or [],
            auth_info=auth_info,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_create(response_xml)

    def domain_update_secdns(
        self,
        name: str,
        add_ds: List[Dict[str, Any]] = None,
        rem_ds: List[Dict[str, Any]] = None,
        add_key: List[Dict[str, Any]] = None,
        rem_key: List[Dict[str, Any]] = None,
        rem_all: bool = False,
        new_max_sig_life: int = None,
        urgent: bool = False,
        cl_trid: str = None,
    ) -> EPPResponse:
        """
        Update DNSSEC data for a domain.

        Args:
            name: Domain name
            add_ds: DS records to add
            rem_ds: DS records to remove
            add_key: Key records to add
            rem_key: Key records to remove
            rem_all: Remove all DNSSEC data
            new_max_sig_life: New maximum signature lifetime
            urgent: Request urgent processing

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_update_secdns(
            domain_name=name,
            add_ds=add_ds,
            rem_ds=rem_ds,
            add_key=add_key,
            rem_key=rem_key,
            rem_all=rem_all,
            new_max_sig_life=new_max_sig_life,
            urgent=urgent,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def domain_info_secdns(
        self,
        name: str,
        auth_info: str = None,
        hosts: str = "all",
        cl_trid: str = None,
    ) -> Tuple[DomainInfo, Optional[SecDNSInfo]]:
        """
        Get domain info including DNSSEC data.

        Args:
            name: Domain name
            auth_info: Optional auth info
            hosts: Host info to return

        Returns:
            Tuple of (DomainInfo, SecDNSInfo or None)

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_info(
            name=name,
            auth_info=auth_info,
            hosts=hosts,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)

        domain_info = XMLParser.parse_domain_info(response_xml)
        secdns_info = XMLParser.parse_secdns_info_extension(response_xml)

        return domain_info, secdns_info

    # =========================================================================
    # Phase 8: IDN Extension Commands
    # =========================================================================

    def domain_create_with_idn(
        self,
        name: str,
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
    ) -> Tuple[DomainCreateResult, Optional[IDNData]]:
        """
        Create an IDN domain with user form and language.

        Args:
            name: Domain name (DNS/ACE form, e.g., xn--mgbh0fb.ae)
            registrant: Registrant contact ID
            user_form: Unicode user form (e.g., مثال)
            language: BCP 47 language tag (e.g., ar, zh, de)
            period: Registration period (default 1)
            period_unit: Period unit - 'y' or 'm' (default: y)
            admin: Admin contact ID
            tech: Tech contact ID
            billing: Billing contact ID
            nameservers: List of nameserver hostnames
            auth_info: Auth info (auto-generated if not provided)

        Returns:
            Tuple of (DomainCreateResult, IDNData with canonical form)

        Raises:
            EPPObjectExists: If domain already exists
            EPPCommandError: If command fails
        """
        if auth_info is None:
            auth_info = self._generate_auth_info()

        xml = XMLBuilder.build_domain_create_with_idn(
            domain_name=name,
            registrant=registrant,
            user_form=user_form,
            language=language,
            period=period,
            period_unit=period_unit,
            admin=admin,
            tech=tech,
            billing=billing,
            nameservers=nameservers or [],
            auth_info=auth_info,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)

        create_result = XMLParser.parse_domain_create(response_xml)
        idn_data = XMLParser.parse_idn_create_extension(response_xml)

        return create_result, idn_data

    def domain_info_idn(
        self,
        name: str,
        auth_info: str = None,
        hosts: str = "all",
        cl_trid: str = None,
    ) -> Tuple[DomainInfo, Optional[IDNData]]:
        """
        Get IDN domain info including user form and language.

        Args:
            name: Domain name
            auth_info: Optional auth info
            hosts: Host info to return

        Returns:
            Tuple of (DomainInfo, IDNData or None)

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_info(
            name=name,
            auth_info=auth_info,
            hosts=hosts,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)

        domain_info = XMLParser.parse_domain_info(response_xml)
        idn_info = XMLParser.parse_idn_info_extension(response_xml)

        return domain_info, idn_info

    # =========================================================================
    # Phase 9: Variant Extension Commands
    # =========================================================================

    def domain_info_variants(
        self,
        name: str,
        variants: str = "all",
        auth_info: str = None,
        hosts: str = "all",
        cl_trid: str = None,
    ) -> Tuple[DomainInfo, Optional[VariantInfo]]:
        """
        Get domain info with variant information.

        Args:
            name: Domain name
            variants: Variant query type: 'all' or 'none'
            auth_info: Optional auth info
            hosts: Host info to return

        Returns:
            Tuple of (DomainInfo, VariantInfo or None)

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_info_with_variant(
            domain_name=name,
            variants=variants,
            auth_info=auth_info,
            hosts=hosts,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)

        domain_info = XMLParser.parse_domain_info(response_xml)
        variant_info = XMLParser.parse_variant_info_extension(response_xml)

        return domain_info, variant_info

    def domain_update_variants(
        self,
        name: str,
        add_variants: List[Dict[str, str]] = None,
        rem_variants: List[str] = None,
        cl_trid: str = None,
    ) -> EPPResponse:
        """
        Update domain variants.

        Args:
            name: Domain name
            add_variants: Variants to add, each dict with:
                - name: DNS form of variant
                - user_form: Unicode user form
            rem_variants: Variant names to remove (DNS form)

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_update_with_variant(
            domain_name=name,
            add_variants=add_variants,
            rem_variants=rem_variants,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    # =========================================================================
    # Phase 10: Sync Extension Commands
    # =========================================================================

    def domain_sync(
        self,
        name: str,
        exp_date: str,
        cl_trid: str = None,
    ) -> EPPResponse:
        """
        Synchronize domain expiry date.

        Args:
            name: Domain name
            exp_date: Target expiry date (YYYY-MM-DDTHH:MM:SS.0Z)

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_update_with_sync(
            domain_name=name,
            exp_date=exp_date,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    # =========================================================================
    # Phase 11: KV Extension Commands
    # =========================================================================

    def domain_create_with_kv(
        self,
        name: str,
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
    ) -> DomainCreateResult:
        """
        Create a domain with key-value metadata.

        Args:
            name: Domain name
            registrant: Registrant contact ID
            kvlists: Key-value lists, each dict with:
                - name: list name
                - items: list of dicts with 'key' and 'value'
            period: Registration period (default 1)
            period_unit: Period unit (default: y)
            admin: Admin contact ID
            tech: Tech contact ID
            billing: Billing contact ID
            nameservers: List of nameserver hostnames
            auth_info: Auth info (auto-generated if not provided)

        Returns:
            DomainCreateResult

        Raises:
            EPPObjectExists: If domain already exists
            EPPCommandError: If command fails

        Example:
            result = client.domain_create_with_kv(
                name="example.ae",
                registrant="contact123",
                kvlists=[
                    {
                        "name": "metadata",
                        "items": [
                            {"key": "category", "value": "premium"},
                            {"key": "source", "value": "auction"}
                        ]
                    }
                ]
            )
        """
        if auth_info is None:
            auth_info = self._generate_auth_info()

        xml = XMLBuilder.build_domain_create_with_kv(
            domain_name=name,
            registrant=registrant,
            kvlists=kvlists,
            period=period,
            period_unit=period_unit,
            admin=admin,
            tech=tech,
            billing=billing,
            nameservers=nameservers or [],
            auth_info=auth_info,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_create(response_xml)

    def domain_update_kv(
        self,
        name: str,
        kvlists: List[Dict[str, Any]],
        cl_trid: str = None,
    ) -> EPPResponse:
        """
        Update domain key-value metadata.

        Args:
            name: Domain name
            kvlists: Key-value lists to set/update

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_update_with_kv(
            domain_name=name,
            kvlists=kvlists,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def domain_info_kv(
        self,
        name: str,
        auth_info: str = None,
        hosts: str = "all",
        cl_trid: str = None,
    ) -> Tuple[DomainInfo, Optional[KVInfo]]:
        """
        Get domain info including key-value metadata.

        Args:
            name: Domain name
            auth_info: Optional auth info
            hosts: Host info to return

        Returns:
            Tuple of (DomainInfo, KVInfo or None)

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_info(
            name=name,
            auth_info=auth_info,
            hosts=hosts,
            cl_trid=self._resolve_cl_trid(cl_trid),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)

        domain_info = XMLParser.parse_domain_info(response_xml)
        kv_info = XMLParser.parse_kv_info_extension(response_xml)

        return domain_info, kv_info
