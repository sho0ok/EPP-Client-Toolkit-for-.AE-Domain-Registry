Name:           epp-client
Version:        1.0.0
Release:        1%{?dist}
Summary:        EPP Client Toolkit for .AE Domain Registry
License:        MIT
URL:            https://github.com/sho0ok/EPP-Client-Toolkit-for-.AE-Domain-Registry
BuildArch:      x86_64

Requires:       python3 >= 3.9
Requires:       openssl

%description
A production-ready EPP (Extensible Provisioning Protocol) client toolkit for
.AE domain registry operations. Provides both Python library and CLI tool.

%install
# Create directories
mkdir -p %{buildroot}/opt/epp-client
mkdir -p %{buildroot}/opt/epp-client/venv
mkdir -p %{buildroot}/etc/epp-client
mkdir -p %{buildroot}/etc/epp-client/tls
mkdir -p %{buildroot}/usr/bin

# Copy application files
cp -r %{_sourcedir}/src %{buildroot}/opt/epp-client/
cp -r %{_sourcedir}/venv/* %{buildroot}/opt/epp-client/venv/

# Copy config files
cp %{_sourcedir}/config/client.yaml %{buildroot}/etc/epp-client/

# Copy CLI wrapper
cp %{_sourcedir}/scripts/epp %{buildroot}/usr/bin/epp

%files
%dir /opt/epp-client
/opt/epp-client/src
/opt/epp-client/venv
%config(noreplace) /etc/epp-client/client.yaml
%dir /etc/epp-client/tls
%attr(755,root,root) /usr/bin/epp

%post
echo ""
echo "=========================================="
echo "EPP Client installed successfully!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Copy your TLS certificates to /etc/epp-client/tls/"
echo "   - client.crt (your certificate)"
echo "   - client.key (your private key)"
echo "   - ca.crt (registry CA certificate)"
echo ""
echo "2. Configure connection:"
echo "   vi /etc/epp-client/client.yaml"
echo ""
echo "3. Test connection:"
echo "   epp --help"
echo ""

%changelog
* Tue Jan 21 2025 AE Registry <support@aeda.ae> - 1.0.0-1
- Initial RPM release
- Full EPP RFC 5730-5734 support
- CLI and Python library included
