use ipnet::Ipv4Net;
use network_interface::NetworkInterface;
use network_interface::Netmask;


#[derive(Debug)]
pub struct VirtualRouter {
    pub name: String,
    pub vrid: u8,
    pub ip_addresses: Vec<Ipv4Net>,
    pub priority: u8,
    pub skew_time: f32,
    pub advert_interval: u8,
    pub master_down_interval: f32,
    pub preempt_mode: bool,
    pub network_interface: String
}

impl VirtualRouter {
    pub fn init(&self) {
        log::info!("Creating Network Interface: {}", self.network_interface);
        let interface = NetworkInterface::new_afinet(
            &self.network_interface, 
            self.ip_addresses[0].addr(), 
            Some(self.ip_addresses[0].netmask()), 
            Some(self.ip_addresses[0].broadcast()), 
            501
        );
        
        println!("{:#?}", interface);
        log::debug!("Successfully created network interface {}", self.network_interface);
        
    }
}