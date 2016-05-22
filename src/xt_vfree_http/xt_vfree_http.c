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

#include "xt_vfree_http.h"

static bool vfree_http_mt4(const struct sk_buff *skb, struct xt_action_param *par)
{
  return false;
}

static bool vfree_http_mt6(const struct sk_buff *skb, struct xt_action_param *par)
{
  return false;
}

static ibxt_vfree_http xt_vfree_httpnt vfree_http_mt_check(const struct xt_mtchk_param *par)
{
  return 0;
}

static void vfree_http_mt_destroy(const struct xt_mtdtor_param *par)
{
}

static struct xt_match vfree_http_mt_reg[] __read_mostly = {
	{
		.name = "vfree_http",
		.revision = 0,
		.family = NFPROTO_IPV4,
		.match = vfree_http_mt4,
		.checkentry = vfree_http_mt_check,
		.destroy = vfree_http_mt_destroy,
		.matchsize = XT_ALIGN(sizeof(struct xt_vfree_http_mtinfo)),
		.me = THIS_MODULE,
	},
	{
		.name = "vfree_http",
		.revision = 0,
		.family = NFPROTO_IPV6,
		.match = vfree_http_mt6,
		.checkentry = vfree_http_mt_check,
		.destroy = vfree_http_mt_destroy,
		.matchsize = XT_ALIGN(sizeof(struct xt_vfree_http_mtinfo)),
		.me = THIS_MODULE,
	},

};

static int __init xt_vfree_http_init(void)
{
	pr_devel("load xt_vfree_http\n");
	return xt_register_matches(vfree_http_mt_reg, ARRAY_SIZE(vfree_http_mt_reg));
}

static void __exit xt_vfree_http_exit(void)
{
	xt_unregister_matches(vfree_http_mt_reg, ARRAY_SIZE(vfree_http_mt_reg));
	pr_devel("unload xt_vfree_http\n");
}

module_init(xt_vfree_http_init);
module_exit(xt_vfree_http_exit);

MODULE_AUTHOR("Rayson Zhu <vfreex@gmail.com>");
MODULE_DESCRIPTION("vfree_http match extension for Xtables");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_vfree_http");
MODULE_ALIAS("ip6t_vfree_http");
