use crate::util;
use std::fmt;

pub struct IpFrame {
    version: String,
    header_length: String,
    total_packet_length: i64,
    identification: String,
    flags: String,
    time_to_live: String,
    pub protocol: (String, String),
    header_checksum: String,
    source_ip: String,
    destination_ip: String,
}

impl fmt::Display for IpFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "IP Frame II {{ Version: {}, Header_length: {}, Total_packet_length: {}, Identification: {}, IP_flags: {}, Time_to_live: {}, Protocol: {}, Header_checksum: {}, Source_IP: {}, Destination_IP: {}  }}", self.version, self.header_length, self.total_packet_length, self.identification, self.flags, self.time_to_live, self.protocol.1, self.header_checksum, self.source_ip, self.destination_ip
        )
    }
}

pub fn convert_ip_address(hex_ip: String) -> String {
    let decode_ip = hex::decode(&hex_ip).unwrap();
    let formatted_ip: String = decode_ip
        .iter()
        .map(|&byte| byte.to_string())
        .collect::<Vec<String>>()
        .join(".");
    return formatted_ip;
}

pub fn identify_os (mut ttl :String) -> String {
    const WINDOWS :&str = "128";
    const LINUX_UNIX :&str = "64";
    const CISCO :&str = "255";
    
    if ttl == WINDOWS {
        ttl = format!("Windows ({})", ttl);
    }else if ttl == LINUX_UNIX {
        ttl = format!("Linux/Unix ({})", ttl);
    }else if ttl == CISCO {
        ttl = format!("Cisco ({})", ttl);
    }else{
        ttl = format!("Unknow TTL ({})", ttl);
    }
    return ttl;
}

pub fn handle_ip_frame(data: &str) -> IpFrame {
    let version: String = data.chars().skip(28).take(1).collect();
    let header_length: String = data.chars().skip(29).take(1).collect();
    let mut identification: String = data.chars().skip(36).take(4).collect();
    let total_packet_length: String = data.chars().skip(32).take(4).collect();
    let total_packet_length = util::decode_total_packet_length(total_packet_length);
    let mut flags: String = data.chars().skip(40).take(2).collect();
    let mut time_to_live: String = data.chars().skip(44).take(2).collect();
    let mut protocol: String = data.chars().skip(46).take(2).collect();
    let flags_binary = util::hex_to_binary(&flags);
    let mut header_checksum: String = data.chars().skip(48).take(4).collect();
    let mut source_ip: String = data.chars().skip(52).take(8).collect();
    let mut destination_ip: String = data.chars().skip(60).take(8).collect();
    flags = handle_ip_flags(flags_binary);

    match util::hex_to_decimal(&time_to_live) {
        Ok(decimal) => {
            time_to_live = decimal.to_string();
        }
        Err(err) => eprintln!("Error converting TTL: {:?}", err),
    }

    match util::hex_to_decimal(&protocol) {
        Ok(decimal) => {
            protocol = decimal.to_string();
        }
        Err(err) => panic!("Error converting PROTOCOL {:?}", err),
    }

    identification = format!("0x{}", identification);
    let protocol :(String, String) = handle_ip_protocols(protocol);
    header_checksum = format!("0x{}", header_checksum);
    source_ip = convert_ip_address(source_ip);
    destination_ip = convert_ip_address(destination_ip);
    time_to_live = identify_os(time_to_live);

    let ip_frame = IpFrame {
        version,
        header_length,
        total_packet_length,
        identification,
        flags,
        time_to_live,
        protocol,
        header_checksum,
        source_ip,
        destination_ip,
    };

    return ip_frame;
}

pub fn handle_ip_flags(flags: i32) -> String {
    const DF: i32 = 0b01000000; // Binary: 01000000
    const MF: i32 = 0b00100000; // Binary: 00100000
    match (flags & DF, flags & MF) {
        (DF, 0) => return String::from("DF is set, MF is not set."),
        (0, MF) => return String::from("MF is set, DF is not set."),
        (DF, MF) => return String::from("DF and MF are both set."),
        (0, 0) => return String::from("Neither DF nor MF is set."),
        _ => return String::from("Unknown combination of DF and MF."),
    }
}

pub fn handle_ip_protocols(protocol: String) -> (String, String) {
    const ICMP: &str = "1";
    const TCP: &str = "6";
    const UDP: &str = "17";

    if protocol == ICMP {
        return (ICMP.to_string(), format!("ICMP ({})", ICMP));
    }
    if protocol == TCP {
        return (TCP.to_string() ,format!("TCP ({})", TCP));
    }
    if protocol == UDP {
        return (UDP.to_string() , format!("UDP ({})", UDP));
    }
    return ("0".to_string(), format!("Unknow IP protocol"));
}
