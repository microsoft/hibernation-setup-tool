OBJS=az-hibernate-agent.o
CFLAGS=-Os -Wall -Wextra -std=gnu17 -fstack-protector-all -fno-plt -D_FORTIFY_SOURCE=1
LDFLAGS=-Wl,-z,relro,-z,now

%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@

az-hibernate-agent: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

all: az-hibernate-agent

.PHONY: clean
clean:
	rm -f $(OBJS)
	rm -f az-hibernate-agent

install: all
	install -m 0755 az-hibernate-agent /usr/sbin
	install -m 0644 az-hibernate-agent.service /etc/systemd/system