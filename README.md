# VFREE HijackFilter

VFREE HijackFilter is a free software to protect you from unwanted Internet hijacking.

Copyright (C) 2016 Rayson Zhu <vfreex@gmail.com>

If you encountered Internet hijacking, call your ISP to stop it!
This software should be your last choice for preventing Internet hijacking.

## 1. Installation

### 1.1 Build

1. Ubuntu

``` bash
apt install make gcc iptables-dev linux-headers-generic pkg-config
make
```

2. Debian

``` bash
apt install make gcc iptables-dev kernel-package pkg-config
make
```

3. Fedora

``` bash
dnf install make gcc iptables-devel kernel-devel pkgconfig
make
```

4. RHEL / CentOS

``` bash
yum install make gcc iptables-devel kernel-devel pkgconfig
make
```

## 1.2 Install

``` bash
make install
```

## 1.3. Uninstall

``` bash
make uninstall
```

## 2. Usage

### 2.1 DNSFilter

DNSFilter is a [Netfilter][1] extension to help you match and filter proofed DNS responses.

Suppose your ISP redirects nonexistent domain names to `192.0.2.1` and `198.51.100.1`.
To match and drop those spoofed DNS responses, we can use following commands:

``` bash
# for IPv4 network
iptables -t mangle -A PREROUTING -p udp --sport 53 -m vfree_dns \
  --a 192.0.2.1,198.51.100.1\
# for IPv6 network
ip6tables -t mangle -A PREROUTING -p udp --sport 53 -m vfree_dns \
  --a 192.0.2.1,198.51.100.1\
  --j DROP
```

Use `-h` option for help.
``` bash
iptables -m vfree_dns -h
```

## 3. TO-DO

- HTTPFilter: a netfilter module to match and filter proofed HTTP message

## 4. LICENSE

This program is distributed under GNU GENERAL PUBLIC LICENSE Version 3.

[1]: http://www.netfilter.org
