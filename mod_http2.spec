# Module Magic Number
%{!?_httpd_mmn: %global _httpd_mmn %(cat %{_includedir}/httpd/.mmn 2>/dev/null || echo 0-0)}

Name:		mod_http2
Version:	1.15.14
Release:	1
Summary:	module implementing HTTP/2 for Apache 2
License:	ASL 2.0
URL:		https://icing.github.io/mod_h2/
Source0:	https://github.com/icing/mod_h2/releases/download/v%{version}/mod_http2-%{version}.tar.gz
BuildRequires:  gcc
BuildRequires:	pkgconfig, httpd-devel >= 2.4.20, libnghttp2-devel >= 1.7.0, openssl-devel >= 1.0.2
Requires:	httpd-mmn = %{_httpd_mmn}, libnghttp2 >= 1.21.1
Conflicts:      httpd < 2.4.25-8

%description
The mod_h2 Apache httpd module implements the HTTP2 protocol (h2+h2c) on
top of libnghttp2 for httpd 2.4 servers.

%prep
%setup -q

%build
%configure
make %{?_smp_mflags} V=1

%install
make DESTDIR=%{buildroot} install
rm -rf %{buildroot}/etc/httpd/share/doc/

# create configuration
mkdir -p %{buildroot}%{_httpd_modconfdir}
echo "LoadModule http2_module modules/mod_http2.so" > %{buildroot}%{_httpd_modconfdir}/10-h2.conf
echo "LoadModule proxy_http2_module modules/mod_proxy_http2.so" > %{buildroot}%{_httpd_modconfdir}/10-proxy_h2.conf

%check
make check

%files
%doc README README.md ChangeLog AUTHORS
%license LICENSE
%config(noreplace) %{_httpd_modconfdir}/10-h2.conf
%config(noreplace) %{_httpd_modconfdir}/10-proxy_h2.conf
%{_httpd_moddir}/mod_http2.so
%{_httpd_moddir}/mod_proxy_http2.so

%changelog
* Thu Mar 14 2019 Joe Orton <jorton@redhat.com> - 1.14.1-1
- update to 1.14.1
