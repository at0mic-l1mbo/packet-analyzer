use crate::util;
use std::fmt;

pub struct TcpFrame {
    src_port :String,
    dst_port :String,
    sequence_number :String,
    acknowledgment_number :String,
    header_length :String,
    flags :String,
    window :String,
    checksum :String,
    urgent_pointer :String,
}

impl fmt::Display for TcpFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "TCP FRAME III {{ Source_port: {}, Destination_port: {}, Sequence_number (raw): {}, Acknowledgment_number: {}, Header_length: {}, Flags: {}, Window: {}, Checksum: {}, Urgent_pointer: {}}}", self.src_port, self.dst_port, self.sequence_number, self.acknowledgment_number, self.header_length, self.flags, self.window, self.checksum, self.urgent_pointer
        )
    }
}

fn discover_tcp_flags(flags: i32) -> String {
    let urg = 32; 
    let ack = 16; 
    let psh = 8; 
    let rst = 4; 
    let syn = 2; 
    let fin = 1; 

    match flags {
        n if n == fin => return format!("FIN"),
        n if n == ack => return format!("ACK"),
        n if n == urg => return format!("URG"),
        n if n == rst => return format!("RST"),
        n if n == syn => return format!("SYN"),
        n if n == psh => return format!("PSH"),
        n if n == urg + ack => return format!("URG + ACK"),
        n if n == psh + ack => return format!("PSH + ACK"),
        n if n == psh + syn => return format!("PSH + SYN"),
        n if n == syn + ack => return format!("SYN + ACK"),
        n if n == ack + fin => return format!("ACK + FIN"),
        n if n == syn + fin => return format!("SYN + FIN"),
        n if n == psh + syn + fin => return format!("PSH + SYN + FIN"),
        _ => return format!("Combinação não reconhecida"),
    }
   
}





pub fn handle_tcp_frame (data :&str) -> TcpFrame {
    let mut src_port :String = data.chars().skip(68).take(4).collect();
    let mut dst_port :String = data.chars().skip(72).take(4).collect();
    let mut sequence_number :String = data.chars().skip(76).take(8).collect();
    let mut acknowledgment_number :String = data.chars().skip(84).take(8).collect();
    let header_length :String = data.chars().skip(92).take(1).collect();
    let mut flags :String = data.chars().skip(93).take(3).collect();
    let mut window :String = data.chars().skip(96).take(4).collect();
    let checksum :String = data.chars().skip(100).take(4).collect();
    let urgent_pointer :String = data.chars().skip(104).take(4).collect();

    match util::hex_to_decimal(&src_port) {
        Ok(decimal) => {
            src_port = decimal.to_string();
        }
        Err(err) => panic!("Error converting port to decimal {:?}", err),
    }

    match util::hex_to_decimal(&dst_port) {
        Ok(decimal) => {
            dst_port = decimal.to_string();
        }
        Err(err) => panic!("Error converting port to decimal {:?}", err),
    }

    match util::hex_to_decimal(&sequence_number) {
        Ok(decimal) => {
            sequence_number = decimal.to_string();
        }
        Err(err) => panic!("Error converting sequence number to decimal {:?}", err),
    }

    match util::hex_to_decimal(&acknowledgment_number) {
        Ok(decimal) => {
           acknowledgment_number = decimal.to_string();
        }
        Err(err) => panic!("Error converting sequence number to decimal {:?}", err),
    }

    match util::hex_to_decimal(&flags) {
        Ok(decimal) => {
           flags = decimal.to_string();
        }
        Err(err) => panic!("Error converting sequence number to decimal {:?}", err),
    }

    match util::hex_to_decimal(&window) {
        Ok(decimal) => {
           window = decimal.to_string();
        }
        Err(err) => panic!("Error converting sequence number to decimal {:?}", err),
    }


    let flags :i32 = match flags.trim().parse(){
        Ok(num) => num,
        Err(_) => 0,
    };
    println!("Flags: {}", flags);
    let flags = discover_tcp_flags(flags);

    let tcp_frame = TcpFrame {
        src_port,
        dst_port,
        sequence_number,
        acknowledgment_number,
        header_length,
        flags,
        window,
        checksum,
        urgent_pointer
    };

    return tcp_frame;
}