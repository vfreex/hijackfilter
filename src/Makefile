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

SUBDIRS := libxt_vfree_dns

BUILD_TARGETS := $(SUBDIRS)
INSTALL_TARGETS := $(SUBDIRS:%=%/install)
UNINSTALL_TARGETS := $(SUBDIRS:%=%/uninstall)
CLEAN_TARGETS := $(SUBDIRS:%=%/clean)

DEBUG ?= 0

all: $(BUILD_TARGETS)

$(BUILD_TARGETS):
	@$(MAKE) -C $@ DEBUG=$(DEBUG)

$(CLEAN_TARGETS):
	@$(MAKE) -C $(@:%/clean=%) clean

$(INSTALL_TARGETS):
	@$(MAKE) -C $(@:%/install=%) install

$(UNINSTALL_TARGETS):
	@$(MAKE) -C $(@:%/uninstall=%) uninstall

install: $(INSTALL_TARGETS)

uninstall: $(UNINSTALL_TARGETS)

clean: $(CLEAN_TARGETS)

.PHONY: $(BUILD_TARGETS) $(INSTALL_TARGETS) $(UNINSTALL_TARGETS) $(CLEAN_TARGETS)
.PHONY: all clean install uninstall
