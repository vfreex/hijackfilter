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
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>
#include <asm/unaligned.h>
#include <net/ipv6.h>
#include "xt_vfree_dns.h"
#include "dns.h"

#define get_u8(X,  O)  (*(const __u8 *)((X) + O))
#define get_u16(X, O)  get_unaligned((const __u16 *)((X) + O))
#define get_u32(X, O)  get_unaligned((const __u32 *)((X) + O))

union vfree_dns_record_group {
	void *data;
	struct vfree_dns_a_item *a;
	struct vfree_dns_aaaa_item *aaaa;
};

struct vfree_dns_record_group_kernel {
	uint16_t flags;
	uint16_t count;
	union vfree_dns_record_group records;
};

static const struct vfree_dns_a_item *binarry_search4(const struct vfree_dns_a_item *addresses, size_t count, const uint32_t *target)
{
	size_t left = 0, right = count, medium;
	while (left < right) {
		medium = left + (right - left) / 2;
		if (addresses[medium].ip < *target)
			left = medium + 1;
		else if (addresses[medium].ip > *target)
			right = medium;
		else
			return addresses + medium;
	}
	return false;
}

static const struct vfree_dns_aaaa_item *binarry_search6(const struct vfree_dns_aaaa_item *addresses, size_t count, const struct in6_addr *target)
{
	size_t left = 0, right = count, medium;
	int cmp;
	while (left < right) {
		medium = left + (right - left) / 2;
		cmp = ipv6_addr_cmp((const struct in6_addr *)addresses[medium].ip, target);
		if (cmp < 0)
			left = medium + 1;
		else if (cmp > 0)
			right = medium;
		else
			return addresses + medium;
	}
	return false;
}

/*
* @dns_message: pointer to DNS header
* @size: size of DNS message, including DNS header
*/
static bool record_match(const struct vfree_dns_record_group_kernel *record_group, const unsigned char *dns_message, unsigned int size)
{
	const struct dns_hdr *dns_header = (const struct dns_hdr *)dns_message;
	int i;
	uint16_t qd, an;
	const unsigned char *p, *tail;

	if (size < sizeof(struct dns_hdr)) {
		pr_devel("message shorter than DNS header\n");
		return false;
	}

	pr_devel("DNS ID: %X\n", ntohs(dns_header->id));
	qd = ntohs(dns_header->qdcount);
	pr_devel(" QDCOUNT: %d\n", qd);
	an = ntohs(dns_header->ancount);
	pr_devel(" ANCOUNT: %d\n", an);
	pr_devel(" NSCOUNT: %d\n", ntohs(dns_header->nscount));
	pr_devel(" ARCOUNT: %d\n", ntohs(dns_header->arcount));

	if (!dns_header->qr) {
		pr_devel("will not match a DNS request\n");
		return false;
	}

	p = dns_message + sizeof(struct dns_hdr);
	tail = dns_message + size;

	// skip Question section
	for (i = 0; i < qd; ++i) {
		uint16_t qtype, qclass;
		if (p >= tail) {
			goto error_reached_end;
		}
		// skip a DNS question
		pr_devel("DNS question:\n");
		// skip QNAME
		while (*p && !(*p & 0xC0)) { // is a label
			if (p + 1 + *p > tail) {
				goto error_reached_end;
			}
			pr_devel("%.*s.\n", *p, p + 1); // print this label
			p += 1 + *p; // skip this lable
		}
		if (*p) { // is a label pointer
			if (p + 2 > tail) {
				goto error_reached_end;
			}
			pr_devel("ptr=%d\n", ntohs(get_u16(p, 0)) & 0x3FFF);
			p += 2; // skip the pointer
		} else { // *p == 0, mark of DNS root in a QNAME
			if (p + 1 > tail) {
				goto error_reached_end;
			}
			p++; // skip the mark
		}
		if (p + 4 > tail) {
			goto error_reached_end;
		}
		qtype = ntohs(get_u16(p, 0));
		qclass = ntohs(get_u16(p, 2));
		pr_devel("qtype=%d, qclass=%d\n", qtype, qclass);
		p += 4; // move to next question
	}

	// visit DNS answer section
	for (i = 0; i < an; ++i) {
		// visit a DNS answer
		uint16_t type, class, rdlength;
		uint32_t ttl;
		if (p >= tail) {
			goto error_reached_end;
		}
		pr_devel("DNS answer:\n");
		// visit NAME
		while (*p && !(*p & 0xC0)) { // is a label
			if (p + 1 + *p > tail) {
				goto error_reached_end;
			}
			pr_devel("%.*s.", *p, p + 1); // print this label
			p += 1 + *p; // skip this lable
		}
		if (*p) { // is a label pointer
			if (p + 2 > tail) {
				goto error_reached_end;
			}
			pr_devel("ptr=%d\n", ntohs(get_u16(p, 0)) & 0x3FFF);
			p += 2; // skip the pointer
		} else { // *p == 0, mark of DNS root in a QNAME
			if (p + 1 > tail) {
				goto error_reached_end;
			}
			p++; // skip the mark
		}
		if (p + 10 > tail) {
			goto error_reached_end;
		}
		type = ntohs(get_u16(p, 0));
		class = ntohs(get_u16(p, 2));
		ttl = ntohl(get_u32(p, 4));
		rdlength = ntohs(get_u16(p, 8));
		pr_devel("type=%d, qclass=%d, ttl=%d, rdlength=%d\n", type, class, ttl, rdlength);
		p += 10; // move to rdata
		if (p + rdlength > tail) {
			goto error_reached_end;
		}
		if (class != DNS_CLASS_IN) {
			pr_devel("will not match answer not for Internet\n");
			continue;
		}
		if ((record_group->flags & XT_VFREE_DNS_A) && type == DNS_TYPE_A) {
			uint32_t address;
			if (rdlength != 4) {
				pr_devel("invalid A record length\n");
				return false;
			}
			address = be32_to_cpu(get_u32(p, 0));
			pr_devel("A %pI4\n", &address);
			if (binarry_search4(record_group->records.a, record_group->count, &address)) {
				pr_devel("address matches (answered address: %pI4)\n", &address);
				return true;
			}
		}
		else if ((record_group->flags & XT_VFREE_DNS_AAAA) && type == DNS_TYPE_AAAA) {
			struct in6_addr address;
			if (rdlength != 16) {
				pr_devel("invalid AAAA record length\n");
				return false;
			}
			memcpy(&address, p, 16);
			pr_devel("A %pI6\n", &address);
			if (binarry_search6(record_group->records.aaaa, record_group->count, &address)) {
				pr_devel("address matches (answered address: %pI6)\n", &address);
				return true;
			}
		}
		else {
			print_hex_dump_bytes("RDATA: ", DUMP_PREFIX_NONE, p, rdlength);
		}
		p += rdlength; // move to next answer
	}
	return false;
error_reached_end:
	pr_devel("unexpectly reached the end of a DNS message\n");
	return false;
}

static bool vfree_dns_mt4(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_vfree_dns_mtinfo *info = par->matchinfo;

	const	struct iphdr *network_header;  // ip header struct
	unsigned int hlen;
	//const	struct tcphdr *tcp_header;     // tcp header struct
	const	struct udphdr *udp_header;     // udp header struct
	//int i;
	unsigned char *dns_message;

	if (!info->priv)
		return false;

	/* must not be a fragment */
	if (par->fragoff != 0) {
		pr_devel("offset found %d\n", par->fragoff);
		return false;
	}

	/* make sure that skb is linear */
	if (skb_is_nonlinear(skb)) {
		pr_devel("nonlinear skb found\n");
		return false;
	}

	network_header = (const struct iphdr *)skb_network_header(skb);
	hlen = ntohs(network_header->tot_len) - ntohs(network_header->ihl * 4); /* hlen = packet-data length */

	if (network_header->protocol == IPPROTO_UDP){
		udp_header = (const struct udphdr *)skb_transport_header(skb);
		pr_devel("---------- matching packet ----------\n");
		//pr_devel(" udp_header - network_header = %d\n", (void*)udp_header - (void*)network_header);
		pr_devel(" skb->head = %p, skb->data = %p, skb->tail = %d, skb->end = %d, skb->len = %d, skb->data_len= %d\n",
			skb->head, skb->data, skb->tail, skb->end, skb->len, skb->data_len);
		pr_devel(" network_header = %p, skb->mac_header = %d, skb->network_header = %d, skb->transport_header = %d\n",
			network_header, skb->mac_header, skb->network_header, skb->transport_header);
		pr_devel(" IN: %s\n",skb->dev->name);
		pr_devel(" Protocol: UDP\n");
		pr_devel(" Length: %d\n",skb->len);
		pr_devel(" TTL: %d\n",network_header->ttl);
		pr_devel(" ID: %d\n",network_header->id);
		pr_devel(" S_PORT: %d\n",ntohs((unsigned short int) udp_header->source));
		pr_devel(" D_PORT: %d\n",ntohs((unsigned short int) udp_header->dest));
		//printk(" @_SRC: %d.%d.%d.%d\n",NIPQUAD(network_header->saddr));
		//printk(" @_DST: %d.%d.%d.%d\n",NIPQUAD(network_header->daddr));
		pr_devel(" SRC: %pI4\n", &network_header->saddr);
		pr_devel(" DST: %pI4\n", &network_header->daddr);

		if (hlen < sizeof(struct udphdr)) {
			pr_devel("UDP header indicated packet larger than it is\n");
			return false;
		}
		hlen -= sizeof(struct udphdr); /* hlen = UDP payload length */
    dns_message = ((unsigned char *)udp_header) + sizeof(struct udphdr);
		//return false;
		return record_match(info->priv, dns_message, hlen);
	}
	return false;
}

static bool vfree_dns_mt6(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_vfree_dns_mtinfo *info = par->matchinfo;

	const	struct ipv6hdr *network_header;  // ip header struct
	unsigned int hlen;
	//const	struct tcphdr *tcp_header;     // tcp header struct
	const	struct udphdr *udp_header;     // udp header struct
	//int i;
	unsigned char *dns_message;

	if (!info->priv)
		return false;

	/* must not be a fragment */
	if (par->fragoff != 0) {
		pr_devel("offset found %d\n", par->fragoff);
		return false;
	}

	/* make sure that skb is linear */
	if (skb_is_nonlinear(skb)) {
		pr_devel("nonlinear skb found\n");
		return false;
	}

	network_header = (const struct ipv6hdr *)skb_network_header(skb);
	hlen = ntohs(network_header->payload_len); /* hlen = packet-data length */

	if (network_header->nexthdr == IPPROTO_UDP){
		udp_header = (const struct udphdr *)skb_transport_header(skb);
		pr_devel("---------- matching packet ----------\n");
		//pr_devel(" udp_header - network_header = %d\n", (void*)udp_header - (void*)network_header);
		pr_devel(" skb->head = %p, skb->mac_header = %d, skb->network_header = %d, skb->transport_header = %d\n",
			skb->head, skb->mac_header, skb->network_header, skb->transport_header);
		pr_devel(" IN: %s\n",skb->dev->name);
		pr_devel(" Protocol: UDP\n");
		pr_devel(" Length: %d\n",skb->len);
		pr_devel(" TTL: %d\n",network_header->hop_limit);
		//pr_devel(" ID: %d\n",network_header->id);
		pr_devel(" S_PORT: %d\n",ntohs((unsigned short int) udp_header->source));
		pr_devel(" D_PORT: %d\n",ntohs((unsigned short int) udp_header->dest));
		//printk(" @_SRC: %d.%d.%d.%d\n",NIPQUAD(network_header->saddr));
		//printk(" @_DST: %d.%d.%d.%d\n",NIPQUAD(network_header->daddr));
		pr_devel(" SRC: %pI6\n", &network_header->saddr);
		pr_devel(" DST: %pI6\n", &network_header->daddr);

		if (hlen < sizeof(struct udphdr)) {
			pr_devel("UDP header indicated packet larger than it is\n");
			return false;
		}
		hlen -= sizeof(struct udphdr); /* hlen = UDP payload length */
	  dns_message = ((unsigned char *)udp_header) + sizeof(struct udphdr);
		//return false;
		return record_match(info->priv, dns_message, hlen);
	}
	return false;
}

static inline int vfree_dns_a_item_compare(const void *lhs, const void *rhs)
{
	struct vfree_dns_a_item *l = (struct vfree_dns_a_item *)lhs,
		*r = (struct vfree_dns_a_item *)rhs;
	return l->ip < r->ip ? -1 : (l->ip > r->ip ? 1 : 0);
}

static inline int vfree_dns_aaaa_item_compare(const void *lhs, const void *rhs)
{
	struct vfree_dns_aaaa_item *l = (struct vfree_dns_aaaa_item *)lhs,
		*r = (struct vfree_dns_aaaa_item *)rhs;
	return ipv6_addr_cmp((const struct in6_addr *)l->ip, (const struct in6_addr *)r->ip);
}

static int vfree_dns_mt_check(const struct xt_mtchk_param *par)
{
	int ret = 0, i;
	struct xt_vfree_dns_mtinfo *info = par->matchinfo;
	struct vfree_dns_a_item *a_item;
	struct vfree_dns_aaaa_item *aaaa_item;
	size_t records_size;

	pr_devel("vfree_dns_mt_check() was called.\n");

	if (info->flags & XT_VFREE_DNS_A) {
		if (info->flags & XT_VFREE_DNS_AAAA) {
			pr_devel("You can specify either XT_VFREE_DNS_A or XT_VFREE_DNS_AAAA, not both.\n");
			return -EINVAL;
		}
		if (info->records_count == 0) {
			pr_devel("No A records to match.\n");
			return -EINVAL;
		}
		pr_devel("There are %zu A records to match.\n", (size_t)info->records_count);
		if (info->records_count > MAX_A_RECORDS) {
			pr_devel("A records limit exceeded: %u\n", MAX_A_RECORDS);
			return -EINVAL;
		}
		info->priv = kmalloc(sizeof(struct vfree_dns_record_group_kernel), GFP_KERNEL);
		pr_devel("kmalloc(): info->priv = %p\n", info->priv);
		if (!info->priv)
			return -ENOMEM;
		records_size = sizeof(struct vfree_dns_a_item) * info->records_count;
		info->priv->records.a = vmalloc(records_size);
		pr_devel("vmalloc(): info->priv->records.a = %p, records_size = %zu\n", info->priv->records.a, records_size);
		if (!info->priv->records.a) {
			ret = ENOMEM;
			goto cleanup_priv;
		}
		info->priv->flags = info->flags;
		info->priv->count = info->records_count;
		for (i = 0; i < info->records_count; ++i) {
			a_item = (struct vfree_dns_a_item *)info->argument + i;
			pr_devel("A record: %pI4/%d\n", &a_item->ip, a_item->prefix);
			info->priv->records.a[i].ip = be32_to_cpu(a_item->ip);
			info->priv->records.a[i].prefix = a_item->prefix;
		}
		sort(info->priv->records.a, info->priv->count, sizeof(struct vfree_dns_a_item), vfree_dns_a_item_compare, NULL);
	}
	else if (info->flags & XT_VFREE_DNS_AAAA) {
		if (info->records_count == 0) {
			pr_devel("No AAAA records to match.\n");
			return -EINVAL;
		}
		pr_devel("There are %zu AAAA records to match.\n", (size_t)info->records_count);
		if (info->records_count > MAX_A_RECORDS) {
			pr_devel("AAAA records limit exceeded: %u\n", MAX_AAAA_RECORDS);
			return -EINVAL;
		}
		info->priv = kmalloc(sizeof(struct vfree_dns_record_group_kernel), GFP_KERNEL);
		pr_devel("kmalloc(): info->priv = %p\n", info->priv);
		if (!info->priv)
			return -ENOMEM;
		records_size = sizeof(struct vfree_dns_aaaa_item) * info->records_count;
		info->priv->records.aaaa = vmalloc(records_size);
		pr_devel("vmalloc(): info->priv->records.aaaa = %p, records_size = %zu\n", info->priv->records.a, records_size);
		if (!info->priv->records.aaaa) {
			ret = ENOMEM;
			goto cleanup_priv;
		}
		info->priv->flags = info->flags;
		info->priv->count = info->records_count;
		for (i = 0; i < info->records_count; ++i) {
			aaaa_item = (struct vfree_dns_aaaa_item *)info->argument + i;
			pr_devel("A record: %pI6/%d\n", &aaaa_item->ip, aaaa_item->prefix);
			memcpy(info->priv->records.aaaa[i].ip, aaaa_item->ip, 128);
			info->priv->records.aaaa[i].prefix = aaaa_item->prefix;
		}
		sort(info->priv->records.aaaa, info->priv->count, sizeof(struct vfree_dns_aaaa_item), vfree_dns_aaaa_item_compare, NULL);
	}
	else {
		pr_devel("Nothing to match.\n");
		return -EINVAL;
	}

	return ret;
cleanup_priv:
	kfree(info->priv);
	return ret;
}

static void vfree_dns_mt_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_vfree_dns_mtinfo *info = par->matchinfo;
	pr_devel("vfree_dns_mt_destroy() was called.\n");
	if (info->priv) {
		if (info->priv->records.data) {
			pr_devel("vfree(): info->priv->records.data = %p\n", info->priv->records.data);
			vfree(info->priv->records.data);
		}
		pr_devel("kfree(): info->priv =%p\n", info->priv);
		kfree(info->priv);
	}
}

static struct xt_match vfree_dns_mt_reg[] __read_mostly = {
	{
		.name = "vfree_dns",
		.revision = 0,
		.family = NFPROTO_IPV4,
		.match = vfree_dns_mt4,
		.checkentry = vfree_dns_mt_check,
		.destroy = vfree_dns_mt_destroy,
		.matchsize = XT_ALIGN(sizeof(struct xt_vfree_dns_mtinfo)),
		.me = THIS_MODULE,
	},
	{
		.name = "vfree_dns",
		.revision = 0,
		.family = NFPROTO_IPV6,
		.match = vfree_dns_mt6,
		.checkentry = vfree_dns_mt_check,
		.destroy = vfree_dns_mt_destroy,
		.matchsize = XT_ALIGN(sizeof(struct xt_vfree_dns_mtinfo)),
		.me = THIS_MODULE,
	},

};

static int __init xt_vfree_dns_init(void)
{
	pr_devel("load xt_vfree_dns\n");
	return xt_register_matches(vfree_dns_mt_reg, ARRAY_SIZE(vfree_dns_mt_reg));
}

static void __exit xt_vfree_dns_exit(void)
{
	xt_unregister_matches(vfree_dns_mt_reg, ARRAY_SIZE(vfree_dns_mt_reg));
	pr_devel("unload xt_vfree_dns\n");
}

module_init(xt_vfree_dns_init);
module_exit(xt_vfree_dns_exit);

MODULE_AUTHOR("Rayson Zhu <vfreex@gmail.com>");
MODULE_DESCRIPTION("vfree_dns match extension for Xtables");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_vfree_dns");
MODULE_ALIAS("ip6t_vfree_dns");
