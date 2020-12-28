# tuntap

TUN/TAP (+ Rust) playground.

# Notes

arping -I mytundev0 168.0.0.1 -> can read() from

arp ping has 46 byte. For example:

```
00 00 08 06 ff ff ff ff         ff ff e6 da 03 04 72 8b         08 06 00 01 08 00 06 04     00 01 e6 da 03 04 72 8b
a8 00 00 01 ff ff ff ff         ff ff a8 00 00 01
```

Last 4 byte are the IP address: a8 00 00 01, i.e., 168.0.0.1.

# References

https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/
https://www.willusher.io/tray_rust/nix/sys/ioctl/index.html
