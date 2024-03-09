/// This takes the configurations from vrrp.conf file
/// and converts them into the VrrpConfig struct
use std::fmt::Debug;
use serde::{Serialize,Deserialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct VrrpConfig {
    instance_name: String,
    state: StateConfig,
    interface: String,
    virtual_router_id: u8,
    priority: u8,
    advert_int: u16,
    authentication: AuthConfig,
    virtual_ipaddress: String
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
enum StateConfig {
    MASTER,
    BACKUP
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct AuthConfig {
    auth_type: String,
    auth_pass: Option<String>
}


#[test]
fn test_full_json() {
    let data = r#"
        {
            "instance_name": "VR_1",
            "state": "MASTER",
            "interface": "enp0s8",
            "virtual_router_id": 51,
            "priority": 255,
            "advert_int": 1,
            "authentication": {
                "auth_type": "PASS",
                "auth_pass": "12345"
            },
            "virtual_ipaddress": "192.168.100.185/24"
        }
    "#;
    let con: VrrpConfig = serde_json::from_str(data).unwrap();
    assert_eq!(con.instance_name, "VR_1".to_string());
    assert_eq!(con.state, StateConfig::MASTER);
    assert_eq!(con.virtual_router_id, 51);
    assert_eq!(con.priority, 255);
    assert_eq!(con.advert_int, 1);
    assert_eq!(con.authentication.clone().auth_type, "PASS".to_string());
    assert_eq!(con.authentication.clone().auth_pass, Some("12345".to_string()));
    assert_eq!(con.virtual_ipaddress, "192.168.100.185/24".to_string());
}


#[test]
fn test_none_values() {
    let data = r#"
    {
        "instance_name": "VR_1",
        "state": "MASTER",
        "interface": "enp0s8",
        "virtual_router_id": 51,
        "priority": 255,
        "advert_int": 1,
        "authentication": {
            "auth_type": "PASS"
        },
        "virtual_ipaddress": "192.168.100.185/24"
    }"#;
    let con: VrrpConfig = serde_json::from_str(data).unwrap();
    assert_eq!(con.instance_name, "VR_1".to_string());
    assert_eq!(con.state, StateConfig::MASTER);
    assert_eq!(con.virtual_router_id, 51);
    assert_eq!(con.priority, 255);
    assert_eq!(con.advert_int, 1);
    assert_eq!(con.authentication.clone().auth_type, "PASS".to_string());
    assert_eq!(con.authentication.clone().auth_pass, None);
    assert_eq!(con.virtual_ipaddress, "192.168.100.185/24".to_string());

}