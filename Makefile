.PHONY: all clean install

INSTALL=install

all:
clean:

prefix=/usr
exec_prefix=$(prefix)
libdir=$(exec_prefix)/lib

install: all
	$(INSTALL) -m 644 -D evohome_net.py $(DESTDIR)$(libdir)/evohome-rf/evohome_net.py
	$(INSTALL) -m 755 -D evohome-rf.py $(DESTDIR)$(libdir)/evohome-rf/evohome-rf.py
	$(INSTALL) -m 755 -D evohome-state.py $(DESTDIR)$(libdir)/evohome-rf/evohome-state.py
