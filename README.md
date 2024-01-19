<h1 align="center">🚧 Network Analyzer</h1>


The project focuses on transforming raw network byte data, sourced from an input file, into human-readable information. The current implementation covers the decoding of Ethernet, ARP, and IP frames, with future plans to extend support for TCP, UDP, and HTTP protocols.

## 🔑 Key Features:

1. **Ethernet Frame Decoding:** The system interprets Ethernet frames, extracting details such as source and destination MAC addresses, and identifying the encapsulated protocol.

2. **ARP Frame Decoding:** Address Resolution Protocol (ARP) frames are parsed to reveal information about the mapping between IP addresses and MAC addresses.

3. **IP Frame Decoding:** Internet Protocol (IP) frames are processed to expose details such as source and destination IP addresses, time-to-live (TTL), and control flags.

## 🔮 Future Enhancements:

1. **TCP/UDP Decoding:** The project aims to extend its capabilities to include the decoding of Transmission Control Protocol (TCP) and User Datagram Protocol (UDP) frames. This will provide insights into data communication at the transport layer.

2. **HTTP Analysis:** Integration of HTTP decoding will enable the examination of application layer data, offering a deeper understanding of web traffic and communication.

## 🏎️ Usage

```rust
cargo run
/home/user/Desktop/file_to_read.txt

```
--- 

<h3>🦄 Author</h3>
<p>At0mic-l1mbo</p>
