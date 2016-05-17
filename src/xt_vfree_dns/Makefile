# VFREE HijackFilter
# Copyright (C) 2016 Rayson Zhu <vfreex@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

obj-m += xt_vfree_dns.o

DESTDIR ?=
PREFIX ?= /usr/local
MODULES_DIR ?= /lib/modules/$(shell uname -r)
INSTALL := install -c
INSTALLDATA := install -m 644

MODULES = $(obj-m:.o=.ko)
KERNEL_DIR = ${MODULES_DIR}/build
INSTALL_MOD_PATH = $(DESTDIR)
INSTALL_MOD_FULLPATH = $(DESTDIR)/$(MODULES_DIR)/extra/vfree

DEBUG ?= 0
ifeq ($(DEBUG), 1)
	ccflags-y :=-DDEBUG
else
	ccflags-y :=-DNDEBUG
endif

AUTO_DEPMOD ?= 1

all: modules

check:
ifeq ($(MODULES_DIR),/lib/modules/)
	$(error 'Failed to locate your kernel module path. Please try defining MODULES_DIR.')
endif

modules: check
	@echo "Building kernel modules: $(obj-m)"
	@make -C ${KERNEL_DIR} M=$$PWD $@

install: modules
	mkdir -p $(INSTALL_MOD_FULLPATH)
	#make -C ${KERNEL_DIR} M=$$PWD $@
	@$(INSTALL) -t $(INSTALL_MOD_FULLPATH) $(MODULES)
ifeq ($(AUTO_DEPMOD), 1)
	@depmod
endif

uninstall:
	@rm -f $(MODULES:%=$(INSTALL_MOD_FULLPATH)/%)
ifeq ($(AUTO_DEPMOD), 1)
	@depmod
endif

clean:
	@make -C ${KERNEL_DIR} M=$$PWD $@

.PHONY: all check install uninstall clean modules
