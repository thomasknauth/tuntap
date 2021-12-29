extern crate libc;

use ifstructs::ifreq;
use std::convert::TryFrom;

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

// Check structure size at compile time.
const _: [u8; 14] = [0; std::mem::size_of::<eth_hdr>()];

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

const MY_ETH_MAC: [u8; 6] = [0x62, 0x00, 0x40, 0xd2, 0xd2, 0xff];
const MY_IP: u32 = 0x0a000002; // 10.0.0.2

const ETHTYPE_IPV4: u16 = 0x0800;
const ETHTYPE_ARP : u16 = 0x0806;
const ETHTYPE_IPV6: u16 = 0x86DD;

const ARP_REQUEST    : u16 = 0x0001;
const ARP_REPLY      : u16 = 0x0002;

const ARP_HW_TYPE_ETHERNET: u16 = 0x0001;

use std::io::{Read, Write};
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::convert::TryInto;

fn handle_arp(buffer: &[u8]) -> Option<Vec<u8>> {

    let eth_hdr_size = core::mem::size_of::<eth_hdr>();
    let offset = eth_hdr_size;
    let in_arp_hdr = arp_hdr::from_bytes(&buffer[offset..]);

    println!("{:x?}", in_arp_hdr);

    if in_arp_hdr.hwtype != ARP_HW_TYPE_ETHERNET {
        return None;
    }

    if in_arp_hdr.protype != ETHTYPE_IPV4 {
        return None;
    }

    assert!(in_arp_hdr.hwsize == 6);
    assert!(in_arp_hdr.prosize == 4);

    let offset = offset + core::mem::size_of::<arp_hdr>();
    let in_arp_ipv4 = arp_ipv4::from_bytes(&buffer[offset..]);

    println!("{:x?}", in_arp_ipv4);

    if in_arp_hdr.opcode != ARP_REQUEST {
        println!("Unknown ARP opcode.");
        return None;
    }

    if in_arp_ipv4.dip != MY_IP {
        return None;
    }

    let mut out_arp_hdr = in_arp_hdr.clone();
    out_arp_hdr.opcode = ARP_REPLY;

    let out_arp_ipv4 = arp_ipv4 {
        smac: MY_ETH_MAC.clone(),
        sip: MY_IP,
        dmac: in_arp_ipv4.smac.clone(),
        dip: in_arp_ipv4.sip };

    let mut bytes = Vec::new();
    bytes.extend(&out_arp_hdr.into_bytes());
    bytes.extend(&out_arp_ipv4.into_bytes());

    return Some(bytes);
}

#[derive(Debug,Copy,Clone,Default)]
#[repr(C, packed)]
struct ipv4_hdr {
    version_ihl: u8,
    tos: u8,
    len: u16,
    id: u16,
    flags_frag_offset: u16,
    ttl: u8,
    proto: u8,
    csum: u16,
    saddr: u32,
    daddr: u32
}

// Compile-time check for size of structure.
const _: [u8; 20] = [0; std::mem::size_of::<ipv4_hdr>()];

impl ipv4_hdr {

    fn from_bytes(raw: &[u8]) -> Option<ipv4_hdr> {
        let mut v = ipv4_hdr::default();

        let r = raw.split_at(1);
        v.version_ihl = u8::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(1);
        v.tos = u8::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(2);
        v.len = u16::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(2);
        v.id = u16::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(2);
        v.flags_frag_offset = u16::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(1);
        v.ttl = u8::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(1);
        v.proto = u8::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(2);
        v.csum = u16::from_be_bytes(r.0.try_into().unwrap());

        let csum = ipv4_checksum(&raw[0..core::mem::size_of::<ipv4_hdr>()]);
        if  csum != 0 {
            println!("Incorrect IPv4 checksum: {:x} vs {:x}", csum, v.csum);
            return None;
        }

        let r = r.1.split_at(4);
        v.saddr = u32::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(4);
        v.daddr = u32::from_be_bytes(r.0.try_into().unwrap());

        Some(v)
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut b = Vec::<u8>::with_capacity(core::mem::size_of::<&Self>());
        b.extend(&self.version_ihl.to_be_bytes());
        b.extend(&self.tos.to_be_bytes());
        b.extend(&self.len.to_be_bytes());
        b.extend(&self.id.to_be_bytes());
        b.extend(&self.flags_frag_offset.to_be_bytes());
        b.extend(&self.ttl.to_be_bytes());
        b.extend(&self.proto.to_be_bytes());
        b.extend(&self.csum.to_be_bytes());
        b.extend(&self.saddr.to_be_bytes());
        b.extend(&self.daddr.to_be_bytes());
        b
    }
}

#[derive(Debug,Copy,Clone,Default)]
#[repr(C, packed)]
struct ipv6_hdr {
    version: u32,
    payload_len: u16,
    next_hdr: u8,
    hop_limit: u8,
    src_addr: [u8; 4*4],
    dst_addr: [u8; 4*4]
}

// Compile-time check for size of structure.
const _: [u8; 40] = [0; std::mem::size_of::<ipv6_hdr>()];

impl ipv6_hdr {

    fn from_bytes(raw: &[u8]) -> ipv6_hdr {
        let mut v = ipv6_hdr::default();

        let r = raw.split_at(4);
        v.version = u32::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(2);
        v.payload_len = u16::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(1);
        v.next_hdr = u8::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(1);
        v.hop_limit = u8::from_be_bytes(r.0.try_into().unwrap());

        let r = r.1.split_at(16);
        v.src_addr.copy_from_slice(r.0);

        let r = r.1.split_at(16);
        v.dst_addr.copy_from_slice(r.0);

        v
    }
     }

/**
 * Compute IPv4 checksum over input array `a`.
 *
 * Nice property about the checksum is that if the input data already
 * contains the checksum, e.g., a received datagram, the function
 * should just return zero to indicate a correct checksum over the
 * data.
 */
fn ipv4_checksum(a: &[u8]) -> u16 {

    let mut csum: u32 = 0;
    let mut len = a.len();

    let mut r = (a, a);

    while len > 1 {

        r = r.1.split_at(2);

        csum += u32::from(u16::from_be_bytes(r.0.try_into().unwrap()));

        len -= 2;
    }

    if len > 0 {
        csum += u32::from(u8::from_be_bytes(r.1.try_into().unwrap()));
    }

    csum = (csum & 0xFFFF) + (csum >> 16);

    !u16::try_from(csum).ok().unwrap()
}

fn handle_ipv6(buffer: &[u8]) -> Option<Vec<u8>> {

    let eth_hdr_size = core::mem::size_of::<eth_hdr>();
    let offset = eth_hdr_size;
    let an_ipv6_hdr = ipv6_hdr::from_bytes(&buffer[offset..]);

    println!("{:x?}", an_ipv6_hdr);

    None
}

fn handle_icmp_4v(buffer: &[u8]) -> Option<Vec<u8>> {

    let in_hdr = icmp_v4_hdr::from_bytes(buffer);
    let hdr_len = core::mem::size_of::<icmp_v4_hdr>();

    if in_hdr.msg_type != ICMP_TYPE_ECHO_REQUEST {
        println!("Unknown ICMP request.");
        return None;
    }

    let req = icmp_v4_echo::from_bytes(&buffer[hdr_len..]);
    println!("icmp hdr {:x?}", in_hdr);
    println!("icmp req {:x?}", req);

    let reply = icmp_v4_echo {
        id: req.id,
        seq: req.seq,
        data: {req.data}
    };

    let out_hdr = icmp_v4_hdr {
        msg_type: ICMP_TYPE_ECHO_REPLY,
        code: 0,
        csum: 0
    };

    let mut bytes = out_hdr.into_bytes();
    bytes.extend(&reply.into_bytes());
    let csum = ipv4_checksum(&bytes);
    bytes[2..4].copy_from_slice(&csum.to_be_bytes());

    return Some(bytes);
}

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_TCP:  u8 = 6;
const IP_PROTO_UDP:  u8 = 17;

fn handle_ipv4(buffer: &[u8]) -> Option<Vec<u8>> {

    let eth_hdr_size = core::mem::size_of::<eth_hdr>();
    let offset = eth_hdr_size;

    let in_ipv4_hdr = match ipv4_hdr::from_bytes(&buffer[offset..]) {
        Some(x) => x,
        None => return None
    };

    let data_start = offset + core::mem::size_of::<ipv4_hdr>();
    let data_end = offset + usize::try_from(in_ipv4_hdr.len).ok().unwrap();
    let data = &buffer[data_start..data_end];

    println!("{:x?}", in_ipv4_hdr);

    match in_ipv4_hdr.proto {
        IP_PROTO_ICMP => {
            let out_data = match handle_icmp_4v(data) {
                Some(x) => x,
                None => {
                    println!("Error handling ICMP packet.");
                    return None;
                }
            };

            let mut out_ip4v_hdr = in_ipv4_hdr.clone();
            out_ip4v_hdr.saddr = in_ipv4_hdr.daddr;
            out_ip4v_hdr.daddr = in_ipv4_hdr.saddr;
            out_ip4v_hdr.ttl = 10;
            out_ip4v_hdr.csum = 0;

            let mut out_bytes = out_ip4v_hdr.into_bytes();

            let csum = ipv4_checksum(&out_bytes);
            out_bytes[10..12].copy_from_slice(&csum.to_be_bytes());
            out_bytes.extend(&out_data);

            return Some(out_bytes);
        },
        IP_PROTO_TCP => todo!(),
        IP_PROTO_UDP => todo!(),
        _ => println!("Cannot handle IP packet: {:x?}", in_ipv4_hdr)
    };

    None
}

const ICMP_TYPE_ECHO_REPLY      : u8 = 0x0;
const ICMP_TYPE_ECHO_REQUEST    : u8 = 0x8;

#[derive(Debug,Copy,Clone,Default)]
#[repr(C, packed)]
struct icmp_v4_hdr {
    msg_type: u8,
    code: u8,
    csum: u16
}

impl icmp_v4_hdr {

    fn from_bytes(b: &[u8]) -> icmp_v4_hdr {
        let mut p = icmp_v4_hdr::default();

        let t = b.split_at(1);
        p.msg_type = u8::from_be_bytes(t.0.try_into().unwrap());

        let t = t.1.split_at(1);
        p.code = u8::from_be_bytes(t.0.try_into().unwrap());

        let t = t.1.split_at(2);
        p.csum = u16::from_be_bytes(t.0.try_into().unwrap());

        p
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut v = Vec::<u8>::with_capacity(core::mem::size_of::<Self>());
        v.extend(&self.msg_type.to_be_bytes());
        v.extend(&self.code.to_be_bytes());
        v.extend(&self.csum.to_be_bytes());
        v
    }
}

#[derive(Debug,Clone,Default)]
#[repr(C)]
struct icmp_v4_echo {
    id: u16,
    seq: u16,
    data: Vec<u8>
}

impl icmp_v4_echo {
    fn from_bytes(s: &[u8]) -> icmp_v4_echo {
        let mut p = icmp_v4_echo::default();

        let t = s.split_at(2);
        p.id = u16::from_be_bytes(t.0.try_into().unwrap());

        let t = t.1.split_at(2);
        p.seq = u16::from_be_bytes(t.0.try_into().unwrap());

        // Remaining bytes go into data
        p.data.extend_from_slice(&t.1[0..]);

        p
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.data.len());
        v.extend(&self.id.to_be_bytes());
        v.extend(&self.seq.to_be_bytes());
        v.extend(&self.data);
        v
    }
}

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
        println!("Read {:?} bytes.", n);

        let in_eth_hdr = eth_hdr::from_bytes(&buffer);

        println!("{:x?}", in_eth_hdr);

        let payload =
            match in_eth_hdr.eth_type {
                ETHTYPE_ARP => handle_arp(&buffer),
                ETHTYPE_IPV6 => handle_ipv6(&buffer),
                ETHTYPE_IPV4 => handle_ipv4(&buffer),
                _ => {
                    println!("Ignoring unknown Ethernet packet.");
                    None
                }
            };

        if payload.is_none() {
            continue;
        }

        let out_eth_hdr = eth_hdr {
            dmac: in_eth_hdr.smac.clone(),
            smac: MY_ETH_MAC.clone(),
            eth_type: in_eth_hdr.eth_type
        };

        let payload = payload.unwrap();

        let mut eth = Vec::<u8>::with_capacity(core::mem::size_of::<eth_hdr>() + payload.len());

        eth.extend(&out_eth_hdr.into_bytes());
        eth.extend(&payload);

        let sent_bytes = f.write(eth.as_slice()).unwrap();

        println!("Sent {} bytes as response.", sent_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_checksum() {
        let bytes: [u8; 20] = [0x45, 0x00, 0x00, 0x54, 0x41, 0xe0, 0x40, 0x00,
                               0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x04,
                               0x0a, 0x00, 0x00, 0x05];

        assert_eq!(ipv4_checksum(&bytes), 0xe4c0);
    }

    #[test]
    fn test_ipv4_hdr() {
        // Capturing byte sequences to test (de)serialization code is
        // easy with `tcpdump -xx` - the `-xx` makes tcpdump also
        // output link-level (Ethernet) headers. The following is an
        // IPv4 header (20 bytes).
        let bytes: [u8; 20] =
            [	0x45, 0x00, 0x00, 0x54, 0x5d, 0xb8, 0x40, 0x00,
              0x40, 0x01, 0xc6, 0xe0, 0x0a, 0x00, 0x02, 0x0f,
              0x0a, 0x00, 0x00, 0x02
            ];

        assert_eq!(&bytes, ipv4_hdr::from_bytes(&bytes).unwrap().into_bytes().as_slice());
        assert_eq!(ipv4_checksum(&bytes), 0);
    }

    #[test]
    fn test_icmp_v4_echo() {
        let bytes: [u8; 64] =
            [0x08, 0x00, 0x44, 0x16, 0x00, 0x1b, 0x00, 0x01,
             0x3a, 0xab, 0xb7, 0x61, 0x00, 0x00, 0x00, 0x00,
             0xf5, 0xed, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
             0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
             0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
             0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
             0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37];

        assert_eq!(&bytes[0..4], icmp_v4_hdr::from_bytes(&bytes[0..4]).into_bytes().as_slice());
        assert_eq!(&bytes[4..], icmp_v4_echo::from_bytes(&bytes[4..]).into_bytes().as_slice());

        // Checksum is zero, since bytes[2..3] already contain the
        // checksum. If bytes[2..3] = 0x0, checksum will be 0x4416;
        assert_eq!(ipv4_checksum(&bytes), 0x0);
    }
}
