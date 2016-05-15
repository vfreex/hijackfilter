/*
 *	VFREE HijackFilter
 *	Copyright (C) 2016 Rayson Zhu <vfreex@gmail.com>
 *
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef _HIJACK_FILTER_DNS_H_
#define _HIJACK_FILTER_DNS_H_

/*
* DNS header and constants
* see https://www.ietf.org/rfc/rfc1035.txt
*/

/* DNS header */
struct dns_hdr
{
	__u16	id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rd :1,
		tc :1,
		aa :1,
		opcode :4,
		qr :1,

		rcode :4,
		cd :1,
		ad :1,
		z :1,
		ra :1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16 qr :1,
		opcode :4,
		aa :1,
		tc :1,
		rd :1,

		ra :1,
		z :1,
		ad :1,
		cd :1,
		rcode :4;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
	__u16 qdcount; // number of question entries
	__u16 ancount; // number of answer entries
	__u16 nscount; // number of authority entries
	__u16 arcount; // number of additional entries
};

/* CLASS & QCLASS values*/
enum {
	DNS_CLASS_IN = 0x0001,
	DNS_CLASS_CS = 0x0002,
	DNS_CLASS_CH = 0x0003,
	DNS_CLASS_HS = 0x0004,
	DNS_QCLASS_IN = DNS_CLASS_IN,
	DNS_QCLASS_CS = DNS_CLASS_CS,
	DNS_QCLASS_CH = DNS_CLASS_CH,
	DNS_QCLASS_HS = DNS_CLASS_HS,
	DNS_QCLASS_ANY = 0x00ff,
};

/* TYPE & QTYPE values*/
enum {
	DNS_TYPE_A = 0x0001,
	DNS_TYPE_NS = 0x0002,
	DNS_TYPE_CNAME = 0x0005,
	DNS_TYPE_PTR = 0x000c,
	DNS_TYPE_MX = 0x000f,
	DNS_TYPE_TXT = 0x0010,
	DNS_TYPE_AAAA = 0x001c,
  DNS_QTYPE_A = DNS_TYPE_A,
  DNS_QTYPE_NS = DNS_TYPE_NS,
  DNS_QTYPE_CNAME = DNS_TYPE_CNAME,
  DNS_QTYPE_PTR = DNS_TYPE_PTR,
  DNS_QTYPE_MX = DNS_TYPE_MX,
  DNS_QTYPE_TXT = DNS_TYPE_TXT,
  DNS_QTYPE_AAAA = DNS_TYPE_AAAA,
	DNS_QTYPE_ANY = 0x00ff,
};

#endif /* end of include guard: _HIJACK_FILTER_DNS_H_ */
