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

SUBDIRS := src

BUILD_TARGETS := $(SUBDIRS)
INSTALL_TARGETS := $(SUBDIRS:%=%/install)
UNINSTALL_TARGETS := $(SUBDIRS:%=%/uninstall)
CLEAN_TARGETS := $(SUBDIRS:%=%/clean)

export DEBUG ?= 0
export DESTDIR ?= test2
export PREFIX ?= /usr/local

PACKAGE_NAME := hijackfilter
PACKAGE_VERSION := $(shell cut -d - -f1 VERSION)
PACKAGE_RELEASE := $(shell cut -d - -f2 VERSION)
DIST_DIR := dist
RPMBUILD_TOPDIR = $(DIST_DIR)/rpmbuild

all: $(BUILD_TARGETS)

$(BUILD_TARGETS):
	@$(MAKE) -C $@

$(CLEAN_TARGETS):
	@$(MAKE) -C $(@:%/clean=%) clean

$(INSTALL_TARGETS):
	@$(MAKE) -C $(@:%/install=%) install

$(UNINSTALL_TARGETS):
	@$(MAKE) -C $(@:%/uninstall=%) uninstall

install: $(INSTALL_TARGETS)

uninstall: $(UNINSTALL_TARGETS)

clean: $(CLEAN_TARGETS)
	@rm -rf -- "$(DIST_DIR)"

dist: clean
	@mkdir -p "$(DIST_DIR)/$(PACKAGE_NAME)-$(PACKAGE_VERSION)" \
		&& cp -a {LICENSE,VERSION,Makefile,README.md,*.spec,src} "$(DIST_DIR)/$(PACKAGE_NAME)-$(PACKAGE_VERSION)"
	@cd "$(DIST_DIR)" && tar -czvf "$(PACKAGE_NAME)-$(PACKAGE_VERSION)".tar.gz "$(PACKAGE_NAME)-$(PACKAGE_VERSION)"

rpm: dist
	@mkdir -p $(RPMBUILD_TOPDIR)
	@rpmbuild --define "_topdir `pwd`/$(RPMBUILD_TOPDIR)" -ta "$(DIST_DIR)/$(PACKAGE_NAME)-$(PACKAGE_VERSION)".tar.gz

.PHONY: $(BUILD_TARGETS) $(INSTALL_TARGETS) $(UNINSTALL_TARGETS) $(CLEAN_TARGETS)
.PHONY: all clean install uninstall dist rpm
