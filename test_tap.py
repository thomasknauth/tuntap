from subprocess import *
import shlex

def test_arp():
    proc = Popen(["./target/debug/tuntap"])

    arping = check_output(shlex.split("arping -c 1 -I mytap0 10.0.0.2"))
