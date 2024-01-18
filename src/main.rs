use std::fmt::format;
use std::num::ParseIntError;
use std::{fmt, fs, io};

pub struct EthFrame {
    dest_mac: String,
    src_mac: String,
    protocol: String,
    choosed_protocol: String,
}

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

pub struct IpFrame {
    version: String,
    header_length: String,
    total_packet_length: i64,
    identification: String,
    flags: String,
    time_to_live: String,
    protocol: String,
    header_checksum: String,
    source_ip: String,
    destination_ip: String,
}

impl fmt::Display for EthFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "Ethernet I {{ Destination_MAC: {}, Source_MAC: {}, Protocol: {}}}",
            self.dest_mac,
            self.src_mac,
            self.protocol // Adicione outros campos conforme necessário
        )
    }
}

impl fmt::Display for ArpFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "ARP Frame II {{ Hardware_Type: {}, Protocol_Type: {}, Hardware_Size: {}, Protocol_Size: {}, Operation_Code: {}, Sender_MAC: {}, Sender_IP: {}, Target_MAC: {}, Target_IP: {}  }}", self.hardware_type, self.protocol_type, self.hardware_size, self.protocol_size, self.operation_code, self.sender_addr, self.sender_ip, self.target_addr, self.target_ip
        )
    }
}

impl fmt::Display for IpFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "IP Frame II {{ Version: {}, Header_length: {}, Total_packet_length: {}, Identification: {}, IP_flags: {}, Time_to_live: {}, Protocol: {}, Header_checksum: {}, Source_IP: {}, Destination_IP: {}  }}", self.version, self.header_length, self.total_packet_length, self.identification, self.flags, self.time_to_live, self.protocol, self.header_checksum, self.source_ip, self.destination_ip
        )
    }
}

pub fn verify_file_path() -> String {
    let mut path: String = String::new();
    println!("Enter here the file path: ");
    io::stdin()
        .read_line(&mut path)
        .expect("Error reading the path!");

    let path: &str = path.trim();
    let read_result = fs::read_to_string(path);
    match read_result {
        Ok(data) => {
            let trimmed_data = data.replace(" ", "");
            if trimmed_data.is_empty() {
                return String::from("The file is empty");
            } else {
                return trimmed_data;
            }
        }
        Err(_) => panic!("Failed to read the file!"),
    }
}
fn hex_to_decimal(hex_string: &str) -> Result<u64, ParseIntError> {
    u64::from_str_radix(hex_string, 16)
}

fn convert_mac_address(hex_address: String) -> String {
    let decode_mac = hex::decode(&hex_address).unwrap();
    let formatted_mac: String = decode_mac
        .iter()
        .map(|&byte| format!("{:02x}", byte))
        .collect::<Vec<String>>()
        .join(":");
    return formatted_mac;
}

fn decode_total_packet_length(total_packet_length: String) -> i64 {
    if let Ok(decoded_bytes) = hex::decode(total_packet_length) {
        if decoded_bytes.len() >= 2 {
            let aux_length = ((decoded_bytes[0] as u16) << 8 | decoded_bytes[1] as u16) as i64;
            return aux_length;
        }
    }
    return -1;
}

fn convert_ip_address(hex_ip: String) -> String {
    let decode_ip = hex::decode(&hex_ip).unwrap();
    let formatted_ip: String = decode_ip
        .iter()
        .map(|&byte| byte.to_string())
        .collect::<Vec<String>>()
        .join(".");
    return formatted_ip;
}

fn handle_ip_flags(flags: i32) -> String {
    const DF: i32 = 0b01000000; // Binário: 01000000
    const MF: i32 = 0b00100000; // Binário: 00100000

    // Verificar combinações específicas
    match (flags & DF, flags & MF) {
        (DF, 0) => return String::from("DF is set, MF is not set."),
        (0, MF) => return String::from("MF is set, DF is not set."),
        (DF, MF) => return String::from("DF and MF are both set."),
        (0, 0) => return String::from("Neither DF nor MF is set."),
        _ => return String::from("Unknown combination of DF and MF."),
    }
}

fn handle_ip_protocols(protocol: String) -> String {
    const ICMP: &str = "1";
    const TCP: &str = "6";
    const UDP: &str = "17";

    if protocol == ICMP {
        return format!("ICMP ({})", ICMP);
    }

    if protocol == TCP {
        return format!("TCP ({})", TCP);
    }

    if protocol == UDP {
        return format!("UDP ({})", UDP);
    }
    panic!("Unknow IP protocol");
}

// Função para converter hexadecimal para binário
fn hex_to_binary(hex: &str) -> i32 {
    i32::from_str_radix(hex, 16).unwrap_or(0)
}

pub fn handle_eth_frame(data: String) -> EthFrame {
    const IP: &str = "0800";
    const ARP: &str = "0806";

    let choosed_protocol: String;
    let mut dest_mac: String = data.chars().take(12).collect();
    let mut src_mac: String = data.chars().skip(12).take(12).collect();
    let mut protocol: String = data.chars().skip(24).take(4).collect();

    dest_mac = convert_mac_address(dest_mac);
    src_mac = convert_mac_address(src_mac);

    if protocol == IP {
        protocol = format!("IP ({})", IP);
        choosed_protocol = IP.to_string();
    } else if protocol == ARP {
        protocol = format!("ARP ({})", ARP);
        choosed_protocol = ARP.to_string();
    } else {
        panic!("Invalid ethernet protocol!");
    }

    let eth_frame = EthFrame {
        dest_mac,
        src_mac,
        protocol,
        choosed_protocol,
    };

    return eth_frame;
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
    sender_addr = convert_mac_address(sender_addr);
    target_addr = convert_mac_address(target_addr);
    sender_ip = convert_ip_address(sender_ip);
    target_ip = convert_ip_address(target_ip);

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

fn handle_ip_frame(data: String) -> IpFrame {
    let version: String = data.chars().skip(28).take(1).collect();
    let header_length: String = data.chars().skip(29).take(1).collect();
    let mut identification: String = data.chars().skip(36).take(4).collect();
    let total_packet_length: String = data.chars().skip(32).take(4).collect();
    let total_packet_length = decode_total_packet_length(total_packet_length);
    let mut flags: String = data.chars().skip(40).take(2).collect();
    let mut time_to_live: String = data.chars().skip(44).take(2).collect();
    let mut protocol: String = data.chars().skip(46).take(2).collect();
    let flags_binary = hex_to_binary(&flags);
    let mut header_checksum :String = data.chars().skip(48).take(4).collect();
    let mut source_ip :String = data.chars().skip(52).take(8).collect();
    let mut destination_ip :String = data.chars().skip(60).take(8).collect();
    flags = handle_ip_flags(flags_binary);

    match hex_to_decimal(&time_to_live) {
        Ok(decimal) => {
            time_to_live = decimal.to_string();
        }
        Err(err) => eprintln!("Error converting TTL: {:?}", err),
    }

    match hex_to_decimal(&protocol) {
        Ok(decimal) => {
            protocol = decimal.to_string();
        }
        Err(err) => panic!("Error converting PROTOCOL {:?}", err),
    }

    identification = format!("0x{}", identification);
    protocol = handle_ip_protocols(protocol);
    header_checksum = format!("0x{}", header_checksum);
    source_ip = convert_ip_address(source_ip);
    destination_ip = convert_ip_address(destination_ip);

    let ip_frame  = IpFrame {
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

fn main() {
    // IP Protocol code
    const IP: &str = "0800";

    // Get the data from the archive
    let data: String = verify_file_path();
    let data2: String = data.clone();
    // Handle data to specific frame
    let eth_frame: EthFrame = handle_eth_frame(data);
    println!("{}", eth_frame);
    if eth_frame.choosed_protocol == IP {
        let ip_frame = handle_ip_frame(data2);
        println!("{}", ip_frame);
    } else {
        let arp_frame: ArpFrame = handle_arp_frame(data2);
        println!("{}", arp_frame);
    }
}
