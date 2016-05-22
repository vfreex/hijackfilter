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
#include "xt_vfree_http.h"

#if DEBUG
#define D(x) x
#else
#define D(x)
#endif

static const struct option vfree_http_mt_opts[] = {
	{.name = "version", .has_arg = true, .val = '1'},
	{.name = "status", .has_arg = true, .val = '2'},
	{NULL},
};

static void vfree_http_mt_help(void)
{
	printf(
"vfree_http match "
"\noptions:\n"
"\t--version\tHTTP version (1.0, 1.1, 1), default 1\n"
"\t--status\tHTTP status code\n"
);
}

static void vfree_http_mt_init(struct xt_entry_match *match)
{
}

static int vfree_http_mt_parse(int c, char **argv, int invert,
    unsigned int *flags, const void *entry, struct xt_entry_match **match)
{
  return false;
}

static void vfree_http_mt_check(unsigned int flags)
{
}

static void vfree_http_mt_print(const void *entry,
	  const struct xt_entry_match *match, int numeric)
{
}

static void vfree_http_mt_save(const void *entry, const struct xt_entry_match *match)
{
}

static struct xtables_match vfree_http_mt_reg = {
	.version       = XTABLES_VERSstatic void vfree_http_mt_save(const void *entry, const struct xt_entry_match *match)
{
	.revision      = 0,
	.family        = PF_INET,
	.size          = XT_ALIGN(sizeof(struct xt_vfree_http_mtinfo)),
	.userspacesize = offsetof(struct xt_vfree_http_mtinfo, priv),
	.help          = vfree_http_mt_help,
	.init          = vfree_http_mt_init,
	.parse         = vfree_http_mt_parse,
	.final_check   = vfree_http_mt_check,
	.print         = vfree_http_mt_print,
	.save          = vfree_http_mt_save,
	.extra_opts    = vfree_http_mt_opts,
};

static struct xtables_match vfree_http_mt6_reg = {
	.version       = XTABLES_VERSION,
	.name          = "vfree_http",
	.revision      = 0,
	.family        = PF_INET6,
	.size          = XT_ALIGN(sizeof(struct xt_vfree_http_mtinfo)),
	.userspacesize = offsetof(struct xt_vfree_http_mtinfo, priv),
	.help          = vfree_http_mt_help,
	.init          = vfree_http_mt_init,
	.parse         = vfree_http_mt_parse,
	.final_check   = vfree_http_mt_check,
	.print         = vfree_http_mt_print,
	.save          = vfree_http_mt_save,
	.extra_opts    = vfree_http_mt_opts,
};

static void _init(void)
{
	xtables_register_match(&vfree_http_mt_reg);
	xtables_register_match(&vfree_http_mt6_reg);
}
