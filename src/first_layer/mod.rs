use crate::util;
use std::fmt;
pub struct EthFrame {
    dest_mac: String,
    src_mac: String,
    protocol: String,
    pub choosed_protocol: String,
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

pub fn handle_eth_frame(data: String) -> EthFrame {
    const IP: &str = "0800";
    const ARP: &str = "0806";

    let choosed_protocol: String;
    let mut dest_mac: String = data.chars().take(12).collect();
    let mut src_mac: String = data.chars().skip(12).take(12).collect();
    let mut protocol: String = data.chars().skip(24).take(4).collect();

    dest_mac = util::convert_mac_address(dest_mac);
    src_mac = util::convert_mac_address(src_mac);

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
