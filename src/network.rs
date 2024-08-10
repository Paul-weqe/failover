use crate::{
    checksum,
    packet::{ARPframe, VrrpPacket},
};
use libc::AF_PACKET;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::io::unix::AsyncFd;

pub fn send_vrrp_packet(ifname: &str, mut packet: VrrpPacket) -> std::io::Result<usize> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(112))).unwrap();
    let _ = sock.bind_device(Some(ifname.as_bytes()));
    let _ = sock.set_broadcast(true);
    let _ = sock.set_ttl(255);
    packet.checksum = checksum::one_complement_sum(&packet.encode(), Some(6));

    let buf: &[u8] = &packet.encode();
    let saddr = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 18), 0);

    sock.send_to(buf, &saddr.into())
}

pub fn send_packet_arp(ifname: &str, mut arp_frame: ARPframe) {
    use libc::{c_void, sendto, sockaddr, sockaddr_ll};
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    let sock_init = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0x0806))).unwrap();

    let _ = sock_init.bind_device(Some(ifname.as_bytes()));
    let _ = sock_init.set_broadcast(true);
    let sock = AsyncFd::new(sock_init).unwrap();

    let c_ifname = match CString::new(ifname) {
        Ok(c_ifname) => c_ifname,
        Err(err) => {
            println!("error...{err}");
            return;
        }
    };
    let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };

    let mut sa = sockaddr_ll {
        sll_family: AF_PACKET as u16,
        sll_protocol: 0x806_u16.to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    unsafe {
        let ptr_sockaddr = std::mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sa);

        match sendto(
            sock.as_raw_fd(),
            &mut arp_frame as *mut _ as *const c_void,
            std::mem::size_of_val(&arp_frame),
            0,
            ptr_sockaddr,
            std::mem::size_of_val(&sa) as u32,
        ) {
            -1 => {
                println!("there is an error!!!");
            }
            fd => {
                println!("fd...{:#?}", fd);
                println!("sent successfully");
            }
        }
    }
}
