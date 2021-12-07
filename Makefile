ifeq ($(DEBUG),1)
CFLAGS += -g -ggdb
endif

CFLAGS += -std=c11

TAP_NAME ?= mytap0

TAP_HW_ADDR ?= 62:00:40:d2:d2:fb
.PHONY: up
up:
	sudo ip tuntap add mode tap name $(TAP_NAME)
	sudo ip link set $(TAP_NAME) up
	sudo ip route add dev $(TAP_NAME) 10.0.0.0/24
	sudo ip link set dev $(TAP_NAME) address $(TAP_HW_ADDR)
#	sudo ip addr add 10.0.0.1/24 dev $(TAP_NAME)

.PHONY: down
down:
	sudo ip tuntap del mode tap name $(TAP_NAME)

.PHONY: check
check:
	pytest-3
	cargo test

