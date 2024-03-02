
use std::net::Ipv4Addr;

fn main() {
    let address = Ipv4Addr::new(192, 168, 0, 1);
    let x = u32::from_be_bytes(address.octets());
    println!("{x}");
}
