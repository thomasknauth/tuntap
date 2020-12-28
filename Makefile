ifeq ($(DEBUG),1)
CFLAGS += -g -ggdb
endif

CFLAGS += -std=c11

TAP_NAME ?= mytap0

.PHONY: up
run:
	sudo ip tuntap add mode tap name $(TAP_NAME)
	sudo ip addr add 168.0.0.1 dev $(TAP_NAME)
	sudo ip link set $(TAP_NAME) up

.PHONY: down
down:
	sudo ip tuntap del mode tap name $(TAP_NAME)
