%define KERNEL_VERSION %(uname -r)
%define XTABLES_LIBDIR %(pkg-config --variable=xtlibdir xtables)
%define MODULES_DIR /lib/modules/%{KERNEL_VERSION}
%define debug_package %{nil}
#%define PACKAGE_VERSION %(cut -d - -f1 VERSION)
#%define PACKAGE_RELEASE %(cut -d - -f2 VERSION)
%define PACKAGE_VERSION 0.0.1
%define PACKAGE_RELEASE 2


Name:           hijackfilter
Version:        %{PACKAGE_VERSION}
Release:        %{PACKAGE_RELEASE}%{?dist}
Summary:        VFREE HijackFilter is a free software to protect you from unwanted Internet hijacking.

License:        GPLv3
URL:            https://github.com/hijackfilter/hijackfilter
Source:         %{name}-%{version}.tar.gz
Requires:       hijackfilter-dnsfilter

%description
VFREE HijackFilter is a set of free software to protect you from Internet hijacking

%package dnsfilter
Version:        %{PACKAGE_VERSION}
Release:        %{PACKAGE_RELEASE}%{?dist}
Summary: DNSFilter is a Netfilter extension to match and filter proofed DNS responses.
BuildRequires:  iptables-devel pkgconfig
Requires: iptables hijackfilter-dnsfilter-kmod  = %{version}

%description dnsfilter
DNSFilter is a Netfilter extension to match and filter proofed DNS responses.

%package dnsfilter-kmod
Version:        %{PACKAGE_VERSION}
Release:        %{PACKAGE_RELEASE}.%(echo %{KERNEL_VERSION} | cut -d . -f1-4 - | tr - _)
Summary: DNSFilter is a Netfilter extension to match and filter proofed DNS responses.
BuildRequires:  kernel-devel
Provides:       hijackfilter-dnsfilter-kmod-common = %{version}

%description dnsfilter-kmod
DNSFilter is a Netfilter extension to match and filter proofed DNS responses.

%prep
%setup -q -n %{name}-%{version}

%build
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install AUTO_DEPMOD=0


%files
%doc README.md
%license LICENSE

%files dnsfilter
%doc README.md
%license LICENSE
%{XTABLES_LIBDIR}/libxt_vfree_dns.so

%files dnsfilter-kmod
%doc README.md
%license LICENSE
%{MODULES_DIR}/extra/vfree/xt_vfree_dns.ko

%post dnsfilter-kmod
depmod

%postun dnsfilter-kmod
depmod

%changelog
* Sun May 15 2016 Rayson Zhu <vfreex@gmail.com>
- First version
