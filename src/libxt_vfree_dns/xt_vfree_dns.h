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
#ifndef _XT_VFREE_DNS_H_
#define _XT_VFREE_DNS_H_

struct vfree_dns_a_item {
	uint32_t ip;
	uint8_t prefix;
};

enum {
	MAX_ARGUMENT_SIZE = 4096,
	MAX_A_RECORDS = MAX_ARGUMENT_SIZE / sizeof(struct vfree_dns_a_item),
};

enum {
	XT_VFREE_DNS_INV = 1 << 0,
	XT_VFREE_DNS_A = 1 << 1,
};

struct xt_vfree_dns_mtinfo {
	uint16_t flags;
	uint16_t records_count;
	uint8_t argument[MAX_ARGUMENT_SIZE];
	/* Used internally by the kernel */
	struct vfree_dns_record_group_kernel *priv;
};

#endif /* end of include guard: _XT_VFREE_DNS_H_ */
