#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

VERSION = $(shell awk 'END { print $$1 }' VERSION)
CFLAGS ?= -Wall -Wextra -g -O2
CFLAGS += -DVERSION=\"$(VERSION)\"

# Note: assignments are ignored for variable overriden on command line VAR=value
# so DESTDIR is ignored for overriden variables
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
BINDIR := $(DESTDIR)$(BINDIR)
MANDIR ?= $(PREFIX)/share/man
MANDIR := $(DESTDIR)$(MANDIR)


pstack : pstack.c
	$(CC) $(CFLAGS) -o pstack pstack.c

clean:
	rm -f pstack

install : pstack
	mkdir -p "$(BINDIR)"
	install -m 755 pstack "$(BINDIR)"
	mkdir -p "$(MANDIR)/man1"
	install -m 644 man1/pstack.1 "$(MANDIR)/man1"

gittag:
	git tag -s pstack-$(VERSION)

archive: gittag
	@rm -rf /tmp/pstack-$(VERSION).tar.gz
	@git archive -o /tmp/pstack-$(VERSION).tar --prefix=pstack-$(VERSION)/ pstack-$(VERSION)
	@cd /tmp; gzip -9 pstack-$(VERSION).tar
	@cp /tmp/pstack-$(VERSION).tar.gz .
	@echo ""
	@echo "The final archive is ./pstack-$(VERSION).tar.gz."
