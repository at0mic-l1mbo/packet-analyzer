use crate::third_layer::tcp::handle_tcp_frame;

mod first_layer;
mod second_layer;
mod third_layer;
mod util;

fn main() {
    // IP Protocol code
    const IP: &str = "0800";

    // Get the data from the archive
    let data: String = util::verify_file_path();
    // Handle data to specific frame
    let eth_frame: first_layer::EthFrame = first_layer::handle_eth_frame(&data);
    println!("{}", eth_frame);
    if eth_frame.choosed_protocol == IP {
        let ip_frame = second_layer::ip::handle_ip_frame(&data);
        println!("{}", ip_frame);
        match ip_frame.protocol.0.as_str() {
           "1" => {

           }
           "6" => {
                let tcp_frame = third_layer::tcp::handle_tcp_frame(&data);
                println!("{}", tcp_frame);
           }

           "7" => {

           }

           _ => {}
        }

    } else {
        let arp_frame = second_layer::arp::handle_arp_frame(data);
        println!("{}", arp_frame);
    }
}
