extern crate libc;

use ifstructs::ifreq;

// Why on earth is this a top-level macro when the documentation is
// under nix::sys::ioctl?!? Took me several hours to figure why
// importing nix::sys::ioctl:: did not work.
use nix::ioctl_write_int;

mod ioctl {
    use super::*;

    const TUNTAP_MAGIC: u8 = b'T';
    const TUNSETIFF: u8 = 202;

    // Using ioctl_write_ptr! did not work. Somehow, the kernel expects
    // an "int" as input.
    ioctl_write_int!(tun_set_interface, TUNTAP_MAGIC, TUNSETIFF);
}

#[derive(Debug,Copy,Clone,Default)]
#[repr(C, packed)]
struct eth_hdr {
    dmac: [u8; 6],
    smac: [u8; 6],
    eth_type: u16,
}

impl eth_hdr {

    fn from_bytes(raw: &[u8]) -> eth_hdr {
        let mut v = eth_hdr::default();

        let r = raw.split_at(6);
        v.dmac.copy_from_slice(r.0);

        let r = r.1.split_at(6);
        v.smac.copy_from_slice(r.0);

        let r = r.1.split_at(2);
        // Note: The code calls u16::from_*big_endian*_bytes() here,
        // since Ethernet uses "network byte order" to encode
        // multi-byte values.
        v.eth_type = u16::from_be_bytes(r.0.try_into().unwrap());

        v
    }

    fn into_bytes(&self) -> Vec<u8> {
        // Must use #[repr(C, packed)] when declaring the struct for
        // core::mem::size_of to return the correct size here.
        let mut v = Vec::with_capacity(core::mem::size_of::<Self>());
        v.extend(&self.dmac);
        v.extend(&self.smac);
        v.extend(&self.eth_type.to_be_bytes());
        v
    }
}

#[derive(Debug,Copy,Clone,Default)]
#[repr(C, packed)]
struct arp_hdr {
    hwtype: u16,
    protype: u16,
    hwsize: u8,
    prosize: u8,
    opcode: u16
}

impl arp_hdr {

    fn from_bytes(raw: &[u8]) -> arp_hdr {
        let mut v = arp_hdr::default();

        let r = raw.split_at(2);
        v.hwtype = u16::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(2);
        v.protype = u16::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(1);
        v.hwsize = u8::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(1);
        v.prosize = u8::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(2);
        v.opcode = u16::from_be_bytes(r.0.try_into().unwrap());

        v
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(core::mem::size_of::<Self>());
        v.extend(&self.hwtype.to_be_bytes());
        v.extend(&self.protype.to_be_bytes());
        v.extend(&self.hwsize.to_be_bytes());
        v.extend(&self.prosize.to_be_bytes());
        v.extend(&self.opcode.to_be_bytes());
        v
    }
}

#[derive(Debug,Copy,Clone,Default)]
#[repr(C, packed)]
struct arp_ipv4 {
    smac: [u8; 6],
    sip: u32,
    dmac: [u8; 6],
    dip: u32
}

impl arp_ipv4 {

    fn from_bytes(raw: &[u8]) -> arp_ipv4 {
        let mut v = arp_ipv4::default();

        let r = raw.split_at(6);
        v.smac.copy_from_slice(r.0);

        let r = r.1.split_at(4);
        v.sip = u32::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(6);
        v.dmac.copy_from_slice(r.0);

        let r = r.1.split_at(4);
        v.dip = u32::from_be_bytes(r.0.try_into().unwrap());

        v
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(core::mem::size_of::<Self>());
        v.extend(&self.smac);
        v.extend(&self.sip.to_be_bytes());
        v.extend(&self.dmac);
        v.extend(&self.dip.to_be_bytes());
        v
    }
}

use std::io::Read;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::convert::TryInto;

fn main() {

    let mut f = OpenOptions::new().read(true).write(true).open("/dev/net/tun").unwrap();

    let mut req: ifreq = ifreq {
        ifr_name: [b'm', b'y', b't', b'a', b'p', b'0', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        // Initialize *exactly* one member of this wonderful union.
        ifr_ifru: ifstructs::ifr_ifru { ifr_slave: [0; 16] }
    };

    unsafe {
        // IFF_NO_PI is essential here. Ignoring the additional four
        // bytes prepended to each incoming packet is easy. Outgoing
        // packets are also prepended with an additional four
        // bytes. This will most likely confuse the receiver. In the
        // case of ARP replies, the kernel will not understand and
        // ignore them if the additional data is present!
        req.ifr_ifru.ifr_flags = (libc::IFF_TAP | libc::IFF_NO_PI).try_into().unwrap();

        ioctl::tun_set_interface(f.as_raw_fd(), &mut req as *mut ifreq as u64).unwrap();
    };

    loop {

        let mut buffer = [0u8; 2048];

        let n = f.read(&mut buffer).unwrap();
        println!("{:x?}", &buffer[0..n]);
    }
}
