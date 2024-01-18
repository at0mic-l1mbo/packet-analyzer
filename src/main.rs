mod first_layer;
mod second_layer;
mod util;

fn main() {
    // IP Protocol code
    const IP: &str = "0800";

    // Get the data from the archive
    let data: String = util::verify_file_path();
    let data2: String = data.clone();
    // Handle data to specific frame
    let eth_frame: first_layer::EthFrame = first_layer::handle_eth_frame(data);
    println!("{}", eth_frame);
    if eth_frame.choosed_protocol == IP {
        let ip_frame = second_layer::ip::handle_ip_frame(data2);
        println!("{}", ip_frame);
    } else {
        let arp_frame = second_layer::arp::handle_arp_frame(data2);
        println!("{}", arp_frame);
    }
}
