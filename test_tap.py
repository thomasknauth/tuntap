from subprocess import *
import shlex
import time

def test_arp():
    proc = Popen(["./target/debug/tuntap"])

    arping = check_output(shlex.split("arping -c 3 -I mytap0 10.0.0.2"))

    proc.terminate()
    rc = proc.wait(1)

def test_ipv4_ping():
    proc_tap = Popen(["./target/debug/tuntap"])

    clients = []

    NR_CLIENTS = 32
    for i in range(NR_CLIENTS):
        client = Popen(shlex.split("ping -c 3 -W 1 10.0.0.2"))
        clients.append(client)

    TIMEOUT_SEC = 5
    start = time.time()

    while time.time() - start < TIMEOUT_SEC:

        if all([c.returncode != None for c in clients]):
            break

        time.sleep(0.5)

    for c in clients:
        c.terminate()

    proc_tap.terminate()
    tap_rc = proc_tap.wait(1)

    assert all([c.poll() == 0 for c in clients])
