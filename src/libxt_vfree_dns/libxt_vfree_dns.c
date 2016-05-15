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
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <xtables.h>
#include "common/list.h"
#include "xt_vfree_dns.h"

#if DEBUG
#define D(x) x
#else
#define D(x)
#endif

static const struct option vfree_dns_mt_opts[] = {
	{.name = "a", .has_arg = true, .val = '1'},
	{NULL},
};

static void vfree_dns_mt_help(void)
{
	printf(
"vfree_dns match "
"\noptions:\n"
"\t--a\ta comma seperated list of IPv4 addresses\n"
);
}

static void vfree_dns_mt_init(struct xt_entry_match *match)
{
}

static int parse_address_list4(const char *in, struct vfree_dns_a_item *out, int max_count, int *count)
{
	int err = 0, i;
	char *copy, *current, *next, *prefix, *prefix_end;
	struct vfree_dns_a_item *record_item;
	struct in_addr *addr;
	unsigned long prefix_val;
	assert(in);
	assert(out);
	if (!in[0])
		return -EINVAL;
	copy = strdup(in);
	if (!copy)
		return -ENOMEM;
	for (i = 0, current = copy; i < max_count && current; i++, current = next) {
		next = strchr(current, ',');
		if (next)
			*next++ = 0;
		record_item = out + i;
		if (!record_item) {
			err = -ENOMEM;
			goto cleanup_copy;
		}
		prefix = strchr(current, '/');
		if (prefix) {
			*prefix++ = 0;
			if (!*prefix) {
				D(printf("Prefix value is missing. at %td\n", prefix - copy));
				err = -EINVAL;
				goto cleanup_copy;
			}
			prefix_val = strtoul(prefix, &prefix_end, 10);
			if (*prefix_end || prefix_val > 32) {
				D(printf("Prefix value is invalid. at %td\n", prefix_end - copy));
				err = -EINVAL;
				goto cleanup_copy;
			}
			record_item->prefix = (uint8_t)prefix_val;
		} else {
			record_item->prefix = 32;
		}
		if (record_item->prefix < 32) {
			D(printf("Specify a subnet is not supported in current version. at %td\n", prefix_end - copy));
			err = -EINVAL;
			goto cleanup_copy;
		}
		addr = xtables_numeric_to_ipaddr(current);
		if (!addr) {
			D(printf("IPv4 address (%s) is invalid. at %td\n", current, current - copy));
			err = -EINVAL;
			goto cleanup_copy;
		}
		memcpy(&record_item->ip, addr, sizeof(struct in_addr));
		D(printf("Parsed IP address: %s/%d. at %td\n", current,
			record_item->prefix, current - copy));
	}
	if (count)
		*count = i;
	if (current) {
		D(printf("Too many IPv4 addresses. limit: %d\n", max_count));
		err = E2BIG;
		goto cleanup_copy;
	}
cleanup_copy:
	free(copy);
	return err;
}

static int vfree_dns_mt_parse(int c, char **argv, int invert,
    unsigned int *flags, const void *entry, struct xt_entry_match **match)
{
	struct xt_vfree_dns_mtinfo *info = (void *)(*match)->data;
	int err, records_count;
	switch (c) {
	case '1': // --a
		xtables_param_act(XTF_ONLY_ONCE, "xt_vfree_dns", "--a", *flags & XT_VFREE_DNS_A);
		xtables_param_act(XTF_NO_INVERT, "xt_vfree_dns", "--a", invert);
		*flags |= XT_VFREE_DNS_A;
		info->flags = *flags;
		err = parse_address_list4(optarg, (struct vfree_dns_a_item *)info->argument, MAX_A_RECORDS, &records_count);
		if (err) {
			xtables_error(PARAMETER_PROBLEM, "xt_vfree_dns: "
				"fail to parse IP address list, error code %d\n", err);
		}
		info->records_count = (uint16_t)records_count; // records_count <= MAX_RECORDS
		D(printf("parsed record count = %d\n", info->records_count));
		return true;
	}
	return false;
}

static void vfree_dns_mt_check(unsigned int flags)
{
	if (!(flags & XT_VFREE_DNS_A))
		xtables_error(PARAMETER_PROBLEM, "xt_vfree_dns: \"--a\" parameter is required.");
}

static void vfree_dns_mt_print(const void *entry,
	  const struct xt_entry_match *match, int numeric)
{
	const struct xt_vfree_dns_mtinfo *info = (const void *)match->data;
	struct vfree_dns_a_item *a_item;
	int i;
	printf(" vfree_dns");
	if (info->flags & XT_VFREE_DNS_A) {
		printf(" IN A");
		for (i = 0; i < info->records_count; ++i) {
			a_item = (struct vfree_dns_a_item *)info->argument + i;
			printf(" %s", xtables_ipaddr_to_numeric((const struct in_addr *)&a_item->ip));
			if (a_item->prefix < 32)
				printf("/%d\n", a_item->prefix);
		}
	}
}

static void vfree_dns_mt_save(const void *entry, const struct xt_entry_match *match)
{
	const struct xt_vfree_dns_mtinfo *info = (const void *)match->data;
	struct vfree_dns_a_item *a_item;
	int i;
	if (info->flags & XT_VFREE_DNS_A) {
		printf(" --a");
		for (i = 0; i < info->records_count; ++i) {
			a_item = (struct vfree_dns_a_item *)info->argument + i;
			printf(i > 0 ? ",%s" : " %s", xtables_ipaddr_to_numeric((const struct in_addr *)&a_item->ip));
			if (a_item->prefix < 32)
				printf("/%d\n", a_item->prefix);
		}
	}
}

static struct xtables_match vfree_dns_mt_reg = {
	.version       = XTABLES_VERSION,
	.name          = "vfree_dns",
	.revision      = 0,
	.family        = PF_INET,
	.size          = XT_ALIGN(sizeof(struct xt_vfree_dns_mtinfo)),
	.userspacesize = offsetof(struct xt_vfree_dns_mtinfo, priv),
	.help          = vfree_dns_mt_help,
	.init          = vfree_dns_mt_init,
	.parse         = vfree_dns_mt_parse,
	.final_check   = vfree_dns_mt_check,
	.print         = vfree_dns_mt_print,
	.save          = vfree_dns_mt_save,
	.extra_opts    = vfree_dns_mt_opts,
};

static struct xtables_match vfree_dns_mt6_reg = {
	.version       = XTABLES_VERSION,
	.name          = "vfree_dns",
	.revision      = 0,
	.family        = PF_INET6,
	.size          = XT_ALIGN(sizeof(struct xt_vfree_dns_mtinfo)),
	.userspacesize = offsetof(struct xt_vfree_dns_mtinfo, priv),
	.help          = vfree_dns_mt_help,
	.init          = vfree_dns_mt_init,
	.parse         = vfree_dns_mt_parse,
	.final_check   = vfree_dns_mt_check,
	.print         = vfree_dns_mt_print,
	.save          = vfree_dns_mt_save,
	.extra_opts    = vfree_dns_mt_opts,
};

static void _init(void)
{
	xtables_register_match(&vfree_dns_mt_reg);
	xtables_register_match(&vfree_dns_mt6_reg);
}
