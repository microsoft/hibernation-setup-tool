OBJS=az-hibernate-agent.o
CFLAGS+=-Os -Wall -Wextra -std=gnu11 -fstack-protector-all -D_FORTIFY_SOURCE=1
LDFLAGS+=-Wl,-z,relro,-z,now

%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@

az-hibernate-agent: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

all: az-hibernate-agent

.PHONY: clean
clean:
	rm -f $(OBJS)
	rm -f az-hibernate-agent

.PHONY: install
install: all
ifneq (,$(wildcard az-hibernate-agent.1))
	install -m 0755 -d $(DESTDIR)/usr/share/man/man1/
	install -m 0644 az-hibernate-agent.1 $(DESTDIR)/usr/share/man/man1/
endif
	install -m 0755 -d $(DESTDIR)/usr/sbin
	install -m 0755 -d $(DESTDIR)/lib/systemd/system/
	install -m 0755 az-hibernate-agent $(DESTDIR)/usr/sbin
	install -m 0644 az-hibernate-agent.service $(DESTDIR)/lib/systemd/system

.PHONY: indent
indent:
	clang-format az-hibernate-agent.c > indented.c
	mv indented.c az-hibernate-agent.c

az-hibernate-agent.1: README.md
	pandoc -f markdown -s -t man README.md -o az-hibernate-agent.1
