

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/failover)

# Failover

Failover is a VRRP(version 2) implementation currently configured for Ubuntu(soon introducing other Linux and windows systems).

If you want to install and run it directly, find information in the [docs](https://failover-docs.readthedocs.io/).


## Using the library in Rust

Some may want to use the library in rust, to run their own custom Virtual Router implementations. 
Below is how this can be done: 

```rust
use failover::{self, router::VirtualRouter};
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use tokio;

async fn main() {

    let vrouter = VirtualRouter::new(
        String::from("VR_1"),
        51, 
        vec![
            Ipv4Net::new(Ipv4Addr::new(192, 168, 100, 120), 255)
        ],
        101, 
        advert_interval: 1,
        preempt_mode: true,
        network_interface: String::from("wlo1")
    );

    tokio::spawn(async {
        failover::run(vrouter).await
    }).await;
} 
```

This will create a Virtual Router named `VR_1`. 

You can customize these configurations for as many virtual routers as you would like to run in your VRRP setup. 
