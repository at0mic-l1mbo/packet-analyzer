use crate::second_layer::ip;
use crate::util;
use std::fmt;

pub struct ArpFrame {
    hardware_type: String,
    protocol_type: String,
    hardware_size: String,
    protocol_size: String,
    operation_code: String,
    sender_addr: String,
    sender_ip: String,
    target_addr: String,
    target_ip: String,
}

impl fmt::Display for ArpFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "ARP Frame II {{ Hardware_Type: {}, Protocol_Type: {}, Hardware_Size: {}, Protocol_Size: {}, Operation_Code: {}, Sender_MAC: {}, Sender_IP: {}, Target_MAC: {}, Target_IP: {}  }}", self.hardware_type, self.protocol_type, self.hardware_size, self.protocol_size, self.operation_code, self.sender_addr, self.sender_ip, self.target_addr, self.target_ip
        )
    }
}

pub fn handle_arp_frame(data: String) -> ArpFrame {
    const ETHERNET_HARDWARE: &str = "0001";
    const ARP_REQUEST: &str = "0001";
    const ARP_REPLY: &str = "0002";

    let mut hardware_type: String = data.chars().skip(28).take(4).collect();
    let protocol_type: String = data.chars().skip(32).take(4).collect();
    let hardware_size: String = data.chars().skip(36).take(2).collect();
    let protocol_size: String = data.chars().skip(38).take(2).collect();
    let mut operation_code: String = data.chars().skip(40).take(4).collect();
    let mut sender_addr: String = data.chars().skip(44).take(12).collect();
    let mut sender_ip: String = data.chars().skip(56).take(8).collect();
    let mut target_addr: String = data.chars().skip(64).take(12).collect();
    let mut target_ip: String = data.chars().skip(76).take(8).collect();

    // Convert IP and MAC to a legible format
    sender_addr = util::convert_mac_address(sender_addr);
    target_addr = util::convert_mac_address(target_addr);
    sender_ip = ip::convert_ip_address(sender_ip);
    target_ip = ip::convert_ip_address(target_ip);

    if hardware_type == ETHERNET_HARDWARE {
        hardware_type = String::from("Ethernet (1)");
    } else {
        panic!("Invalid hardware type!");
    }

    if operation_code == ARP_REPLY {
        operation_code = String::from("reply (2)");
    } else if operation_code == ARP_REQUEST {
        operation_code = String::from("request (1)");
    } else {
        panic!("Invalid operation code");
    }

    let arp_frame = ArpFrame {
        hardware_type,
        protocol_type,
        hardware_size,
        protocol_size,
        operation_code,
        sender_addr,
        sender_ip,
        target_addr,
        target_ip,
    };

    return arp_frame;
}
