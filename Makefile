OBJS=hibernation-setup-tool.o
CFLAGS+=-Os -Wall -Wextra -std=gnu11 -fstack-protector-all -D_FORTIFY_SOURCE=1
LDFLAGS+=-Wl,-z,relro,-z,now

%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@

hibernation-setup-tool: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

all: hibernation-setup-tool

debug: CFLAGS += -DDEBUG -g -O0
debug: hibernation-setup-tool

.PHONY: clean
clean:
	rm -f $(OBJS)
	rm -f hibernation-setup-tool

.PHONY: install
install: all
ifneq (,$(wildcard hibernation-setup-tool.1))
	install -m 0755 -d $(DESTDIR)/usr/share/man/man1/
	install -m 0644 hibernation-setup-tool.1 $(DESTDIR)/usr/share/man/man1/
endif
	install -m 0755 -d $(DESTDIR)/usr/sbin
	install -m 0755 -d $(DESTDIR)/lib/systemd/system/
	install -m 0755 hibernation-setup-tool $(DESTDIR)/usr/sbin
	install -m 0644 hibernation-setup-tool.service $(DESTDIR)/lib/systemd/system

.PHONY: indent
indent:
	clang-format hibernation-setup-tool.c > indented.c
	mv indented.c hibernation-setup-tool.c

hibernation-setup-tool.1: README.md
	pandoc -f markdown -s -t man README.md -o hibernation-setup-tool.1
