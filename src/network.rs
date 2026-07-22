use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;

use libc::{AF_PACKET, PACKET_OUTGOING, c_void, sendto, sockaddr, sockaddr_ll};
use socket2::{
    Domain, InterfaceIndexOrAddress, Protocol, SockAddr, Socket, Type,
};
use tokio::io::unix::AsyncFd;

use crate::packet::{ARPframe, VrrpPacket};

// IANA-assigned IP protocol number for VRRP.
const VRRP_PROTOCOL_NUMBER: i32 = 112;
const VRRP_MCAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);

fn if_index(ifname: &str) -> io::Result<u32> {
    let c_ifname = CString::new(ifname)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let idx = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(idx)
}

/// Builds a `sockaddr_ll` (wrapped as a `SockAddr`) identifying `ifindex`
/// for the given ARP ethertype (`ETH_P_ARP`), for use with AF_PACKET
/// sockets.
fn arp_link_addr(ifindex: u32) -> SockAddr {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    unsafe {
        let sll =
            (&mut storage as *mut libc::sockaddr_storage).cast::<sockaddr_ll>();
        (*sll).sll_family = AF_PACKET as u16;
        (*sll).sll_protocol = (libc::ETH_P_ARP as u16).to_be();
        (*sll).sll_ifindex = ifindex as i32;
        (*sll).sll_halen = 6;
        SockAddr::new(storage, size_of::<sockaddr_ll>() as libc::socklen_t)
    }
}

/// Sends a single VRRP advertisement to the VRRP multicast group
/// (224.0.0.18) over `ifname`, sourced from `src_ip`.
///
/// Opens a fresh socket per call: VRRP advertisements are infrequent (once
/// per advertisement interval, typically ~1s), so the overhead of a
/// throwaway socket is negligible next to the simplicity it buys.
/// `ifname` is the name of the mac-vlan interface.
pub fn send_vrrp_packet(
    ifname: &str,
    src_ip: Ipv4Addr,
    packet: VrrpPacket,
) -> io::Result<usize> {
    let sock = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(VRRP_PROTOCOL_NUMBER)),
    )?;
    sock.bind_device(Some(ifname.as_bytes()))?;
    sock.bind(&SocketAddrV4::new(src_ip, 0).into())?;
    sock.set_ttl(255)?;
    sock.set_multicast_ttl_v4(255)?;

    let buf: &[u8] = &packet.encode();
    let saddr = SocketAddrV4::new(VRRP_MCAST_ADDR, 0);

    sock.send_to(buf, &saddr.into())
}

/// Sends a single ARP frame over `ifname`.
pub fn send_packet_arp(ifname: &str, arp_frame: ARPframe) {
    let sock = match Socket::new(
        Domain::PACKET,
        Type::RAW,
        Some(Protocol::from(i32::from((libc::ETH_P_ARP as u16).to_be()))),
    ) {
        Ok(sock) => sock,
        Err(err) => {
            log::warn!("Unable to create ARP send socket: {err}");
            return;
        }
    };
    let _ = sock.bind_device(Some(ifname.as_bytes()));
    let _ = sock.set_broadcast(true);

    let ifindex = match if_index(ifname) {
        Ok(idx) => idx,
        Err(err) => {
            log::warn!("Unable to resolve ifindex for {ifname}: {err}");
            return;
        }
    };
    let dest = arp_link_addr(ifindex);

    unsafe {
        match sendto(
            sock.as_raw_fd(),
            &arp_frame as *const _ as *const c_void,
            size_of_val(&arp_frame),
            0,
            dest.as_ptr().cast::<sockaddr>(),
            dest.len(),
        ) {
            -1 => {
                log::warn!("Problem sending ARP message");
            }
            _fd => {}
        }
    }
}

/// A raw IPv4 socket bound to `ifname`, listening on the VRRP protocol
/// (112) as a member of the VRRP multicast group (224.0.0.18). Used
/// instead of a promiscuous datalink capture so that we only ever hear
/// about VRRP traffic actually addressed to the group, and can await it
/// asynchronously without blocking a tokio worker thread.
pub(crate) struct VrrpListener {
    inner: AsyncFd<Socket>,
}

impl VrrpListener {
    pub(crate) fn bind(ifname: &str) -> io::Result<Self> {
        let sock = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(VRRP_PROTOCOL_NUMBER)),
        )?;
        sock.bind_device(Some(ifname.as_bytes()))?;

        let ifindex = if_index(ifname)?;
        sock.join_multicast_v4_n(
            &VRRP_MCAST_ADDR,
            &InterfaceIndexOrAddress::Index(ifindex),
        )?;

        sock.set_nonblocking(true)?;
        Ok(Self {
            inner: AsyncFd::new(sock)?,
        })
    }

    /// Waits for and returns the next VRRP IP datagram received on this
    /// socket, IP header included.
    pub(crate) async fn recv(&self) -> io::Result<Vec<u8>> {
        loop {
            let mut guard = self.inner.readable().await?;
            let mut buf = [MaybeUninit::<u8>::uninit(); 512];
            match guard.try_io(|inner| inner.get_ref().recv(&mut buf)) {
                Ok(Ok(n)) => {
                    let data = unsafe {
                        std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n)
                    };
                    return Ok(data.to_vec());
                }
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }
}

/// A raw AF_PACKET socket bound to `ifname`, listening for ARP
/// (`ETH_P_ARP`) frames.
///
/// AF_PACKET sockets receive a copy of every frame the host transmits on
/// the interface, not just what it receives (see `packet(7)`). Left
/// unfiltered, our own gratuitous/reply ARP frames get fed straight back
/// into the ARP handler, which replies to them, which loops back again,
/// producing a continuous stream of ARP traffic instead of one gratuitous
/// burst. `recv` filters those `PACKET_OUTGOING` copies out at the socket
/// layer so callers never see them.
pub(crate) struct ArpListener {
    inner: AsyncFd<Socket>,
}

impl ArpListener {
    pub(crate) fn bind(ifname: &str) -> io::Result<Self> {
        let sock = Socket::new(
            Domain::PACKET,
            Type::RAW,
            Some(Protocol::from(i32::from((libc::ETH_P_ARP as u16).to_be()))),
        )?;

        let ifindex = if_index(ifname)?;
        sock.bind(&arp_link_addr(ifindex))?;

        sock.set_nonblocking(true)?;
        Ok(Self {
            inner: AsyncFd::new(sock)?,
        })
    }

    /// Waits for and returns the next ARP ethernet frame received on this
    /// socket that isn't a loopback copy of our own outgoing traffic.
    pub(crate) async fn recv(&self) -> io::Result<Vec<u8>> {
        loop {
            let mut guard = self.inner.readable().await?;
            let mut buf = [MaybeUninit::<u8>::uninit(); 128];
            let io_result =
                guard.try_io(|inner| inner.get_ref().recv_from(&mut buf));
            let (n, addr) = match io_result {
                Ok(Ok(pair)) => pair,
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            };

            let pkttype =
                unsafe { (*addr.as_ptr().cast::<sockaddr_ll>()).sll_pkttype };
            if pkttype == PACKET_OUTGOING {
                continue;
            }

            let data = unsafe {
                std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n)
            };
            return Ok(data.to_vec());
        }
    }
}
