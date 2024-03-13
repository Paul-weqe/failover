
use rand::{distributions::Alphanumeric, Rng};

pub fn priority() -> u8 { 100 }
pub fn advert_int() -> u8 { 1 }
pub fn preempt_mode() -> bool { true }

// create a name for a random network interface with name failnet-{random-5-letter-string}
pub fn network_interface() -> String {
    let res = "failnet-".to_string();
    let s: String =  rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(5)
        .map(char::from)
        .collect();
    res + s.as_str()
}