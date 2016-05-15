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

XTABLES_LIBS := libxt_vfree_dns.so
MODULES := xt_vfree_dns.ko
INCLUDES :=  -I../

DESTDIR :=
PREFIX := /usr/local
INSTALL := install -c
INSTALLDATA := install -m 644
XTABLES_LIBDIR := $(shell pkg-config --variable=xtlibdir xtables)
MODULES_DIR := /lib/modules/$(shell uname -r)

INSTALL_MODULES_DIR = $(DESTDIR)/$(MODULES_DIR)/extra/vfree
INSTALL_XTABLES_LIBDIR = $(DESTDIR)/$(XTABLES_LIBDIR)
DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS :=-Wall -g3 -DDEBUG
else
	CFLAGS :=-O2 -Wall -DNDEBUG
endif

all: build

check:
ifeq ($(XTABLES_LIBDIR),)
	$(error 'Failed to locate your Xtables extension path. Please try defining XTABLES_LIBDIR.')
endif
ifeq ($(MODULES_DIR),/lib/modules/)
	$(error 'Failed to locate your kernel module path. Please try defining MODULES_DIR.')
endif

build: check $(XTABLES_LIBS) modules

lib%.so: lib%.o
	@$(CC) -shared -fPIC -o $@ $^

lib%.o: lib%.c
	@$(CC) $(CFLAGS) $(INCLUDES) -D_INIT=lib$*_init -fPIC -c -o $@ $<

modules: $(MODULES)

$(MODULES):
	@$(MAKE) -f Kbuild obj-m="$(MODULES:.ko=.o)" DEBUG=$(DEBUG) modules

modules/install: modules
	@mkdir -p $(INSTALL_MODULES_DIR)
	@$(INSTALL) -t $(INSTALL_MODULES_DIR) $(MODULES)

modules/uninstall:
	@rm -f $(MODULES:%=$(INSTALL_MODULES_DIR)/%)

modules/clean:
	@$(MAKE) -f Kbuild clean

clean: modules/clean
	@rm -f *.o $(XTABLES_LIBS)

install: all modules/install
	@mkdir -p $(INSTALL_XTABLES_LIBDIR)
	@$(INSTALL) -t $(INSTALL_XTABLES_LIBDIR) $(XTABLES_LIBS)

uninstall: modules/uninstall
	@rm -f $(XTABLES_LIBS:%=$(INSTALL_XTABLES_LIBDIR)/%)

.PHONY: all check build clean install uninstall
.PHONY: modules modules/clean modules/install modules/uninstall
