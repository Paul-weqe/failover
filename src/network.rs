use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;

use libc::{AF_PACKET, PACKET_OUTGOING, c_void, sendto, sockaddr, sockaddr_ll};
use socket2::{
    Domain, InterfaceIndexOrAddress, Protocol, SockAddr, Socket, Type,
};
use tokio::io::unix::AsyncFd;

use crate::packet::{
    ARPframe, ALL_NODES_V6_MCAST_ADDR, NdpNeighborAdvertisement, VrrpPacket,
    VRRP_V6_MCAST_ADDR,
};

// IANA-assigned IP protocol numbers.
const VRRP_PROTOCOL_NUMBER: i32 = 112;
const ICMPV6_PROTOCOL_NUMBER: i32 = 58;

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
pub fn send_vrrp_packet_v4(
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

    let buf: &[u8] = &packet.encode(IpAddr::V4(src_ip));
    let saddr = SocketAddrV4::new(VRRP_MCAST_ADDR, 0);

    sock.send_to(buf, &saddr.into())
}

/// IPv6 counterpart of [`send_vrrp_packet_v4`]: sends to the VRRP IPv6
/// multicast group (ff02::12) over `ifname`, sourced from `src_ip`.
pub fn send_vrrp_packet_v6(
    ifname: &str,
    src_ip: Ipv6Addr,
    packet: VrrpPacket,
) -> io::Result<usize> {
    let sock = Socket::new(
        Domain::IPV6,
        Type::RAW,
        Some(Protocol::from(VRRP_PROTOCOL_NUMBER)),
    )?;
    sock.bind_device(Some(ifname.as_bytes()))?;
    sock.bind(&SocketAddrV6::new(src_ip, 0, 0, 0).into())?;
    sock.set_unicast_hops_v6(255)?;
    sock.set_multicast_hops_v6(255)?;

    let buf: &[u8] = &packet.encode(IpAddr::V6(src_ip));
    let saddr = SocketAddrV6::new(VRRP_V6_MCAST_ADDR, 0, 0, 0);

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

/// Sends a single (gratuitous) Neighbor Advertisement to the all-nodes
/// multicast group over `ifname` -- IPv6's equivalent of [`send_packet_arp`]
/// for announcing a virtual IP's new owner.
pub fn send_neighbor_advertisement(
    ifname: &str,
    target_addr: Ipv6Addr,
    na: NdpNeighborAdvertisement,
) {
    let sock = match Socket::new(
        Domain::IPV6,
        Type::RAW,
        Some(Protocol::from(ICMPV6_PROTOCOL_NUMBER)),
    ) {
        Ok(sock) => sock,
        Err(err) => {
            log::warn!("Unable to create NDP send socket: {err}");
            return;
        }
    };
    let _ = sock.bind_device(Some(ifname.as_bytes()));

    let dst = ALL_NODES_V6_MCAST_ADDR;
    let buf = na.encode(target_addr, dst);
    let saddr = SocketAddrV6::new(dst, 0, 0, 0);
    if let Err(err) = sock.send_to(&buf, &saddr.into()) {
        log::warn!("Problem sending NDP neighbor advertisement on {ifname}: {err}");
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
    /// socket, IP header included (an IPv4 raw socket's receive path
    /// includes the IP header, unlike IPv6's).
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

/// IPv6 counterpart of [`VrrpListener`]. Unlike an IPv4 raw socket, an
/// IPv6 raw socket's receive path does *not* include the IP header, so
/// `recv` here returns the VRRP payload directly along with the sender's
/// address (recovered from the socket's peer address, since it isn't in
/// the payload).
pub(crate) struct VrrpListenerV6 {
    inner: AsyncFd<Socket>,
}

impl VrrpListenerV6 {
    pub(crate) fn bind(ifname: &str) -> io::Result<Self> {
        let sock = Socket::new(
            Domain::IPV6,
            Type::RAW,
            Some(Protocol::from(VRRP_PROTOCOL_NUMBER)),
        )?;
        sock.bind_device(Some(ifname.as_bytes()))?;

        let ifindex = if_index(ifname)?;
        sock.join_multicast_v6(&VRRP_V6_MCAST_ADDR, ifindex)?;

        sock.set_nonblocking(true)?;
        Ok(Self {
            inner: AsyncFd::new(sock)?,
        })
    }

    pub(crate) async fn recv(&self) -> io::Result<(Vec<u8>, Ipv6Addr)> {
        loop {
            let mut guard = self.inner.readable().await?;
            let mut buf = [MaybeUninit::<u8>::uninit(); 512];
            match guard.try_io(|inner| inner.get_ref().recv_from(&mut buf)) {
                Ok(Ok((n, addr))) => {
                    let src = addr
                        .as_socket_ipv6()
                        .map(|s| *s.ip())
                        .unwrap_or(Ipv6Addr::UNSPECIFIED);
                    let data = unsafe {
                        std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n)
                    };
                    return Ok((data.to_vec(), src));
                }
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }
}

/// A raw ICMPv6 socket bound to `ifname`, used to send and receive
/// Neighbor Solicitation/Advertisement messages -- IPv6's equivalent of
/// [`ArpListener`]. Only joins the all-nodes multicast group; it does not
/// join each configured address's solicited-node multicast group, so a
/// Neighbor Solicitation addressed strictly to a solicited-node group
/// (rather than all-nodes) may not reach this socket depending on kernel
/// multicast filtering. Good enough to send/receive gratuitous NAs, which
/// is the ARP-equivalent behaviour this crate relies on.
pub(crate) struct NdpListener {
    inner: AsyncFd<Socket>,
}

impl NdpListener {
    pub(crate) fn bind(ifname: &str) -> io::Result<Self> {
        let sock = Socket::new(
            Domain::IPV6,
            Type::RAW,
            Some(Protocol::from(ICMPV6_PROTOCOL_NUMBER)),
        )?;
        sock.bind_device(Some(ifname.as_bytes()))?;

        let ifindex = if_index(ifname)?;
        sock.join_multicast_v6(&ALL_NODES_V6_MCAST_ADDR, ifindex)?;

        sock.set_nonblocking(true)?;
        Ok(Self {
            inner: AsyncFd::new(sock)?,
        })
    }

    pub(crate) async fn recv(&self) -> io::Result<(Vec<u8>, Ipv6Addr)> {
        loop {
            let mut guard = self.inner.readable().await?;
            let mut buf = [MaybeUninit::<u8>::uninit(); 128];
            match guard.try_io(|inner| inner.get_ref().recv_from(&mut buf)) {
                Ok(Ok((n, addr))) => {
                    let src = addr
                        .as_socket_ipv6()
                        .map(|s| *s.ip())
                        .unwrap_or(Ipv6Addr::UNSPECIFIED);
                    let data = unsafe {
                        std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n)
                    };
                    return Ok((data.to_vec(), src));
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
