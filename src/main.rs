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
        req.ifr_ifru.ifr_flags = nix::net::if_::InterfaceFlags::IFF_TAP.bits().try_into().unwrap();

        ioctl::tun_set_interface(f.as_raw_fd(), &mut req as *mut ifreq as u64).unwrap();
    };

    loop {

        let mut buffer = [0u8; 2048];

        let n = f.read(&mut buffer).unwrap();
        println!("{:x?}", &buffer[0..n]);
    }
}
