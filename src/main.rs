mod defaults;
mod config;
mod router;
mod converter;
mod network;


use std::{error::Error, fs::File, io::BufReader, path::Path, sync::Arc};
use tokio_tun::Tun;
use std::fs::ReadDir;
use simple_logger::SimpleLogger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>>{
    
    SimpleLogger::new().with_colors(true).init().unwrap();
    let config = read_config_from_json_file("./vrrp-config.json")?;
    let vr = converter::config_to_vr(&config);
    vr.init();
    network::send_multicast(vr);

    // let tun = Arc::new(
    //     Tun::builder()
    //         .name("trial-tun")
    //         .tap(false)
    //         .packet_info(false)
    //         .up()
    //         .try_build()
    //         .unwrap()
    // );

    // let mut buf = [0u8; 1024];
    // loop {
    //     let n = tun.recv(&mut buf).await.unwrap();
    //     println!("reading {} bytes: {:?}", n, &buf[..n]);
    // }

    Ok(())
}


fn read_config_from_json_file<P: AsRef<Path>>(path: P) -> Result<config::VRConfig, Box<dyn Error>> {
    log::debug!("READING FROM FILE {:?}", path.as_ref().as_os_str());
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}
