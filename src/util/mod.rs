use std::num::ParseIntError;
use std::{fs, io};

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

pub fn hex_to_decimal(hex_string: &str) -> Result<u64, ParseIntError> {
    u64::from_str_radix(hex_string, 16)
}

pub fn convert_mac_address(hex_address: String) -> String {
    let decode_mac = hex::decode(&hex_address).unwrap();
    let formatted_mac: String = decode_mac
        .iter()
        .map(|&byte| format!("{:02x}", byte))
        .collect::<Vec<String>>()
        .join(":");
    return formatted_mac;
}

pub fn decode_total_packet_length(total_packet_length: String) -> i64 {
    if let Ok(decoded_bytes) = hex::decode(total_packet_length) {
        if decoded_bytes.len() >= 2 {
            let aux_length = ((decoded_bytes[0] as u16) << 8 | decoded_bytes[1] as u16) as i64;
            return aux_length;
        }
    }
    return -1;
}

pub fn hex_to_binary(hex: &str) -> i32 {
    i32::from_str_radix(hex, 16).unwrap_or(0)
}
