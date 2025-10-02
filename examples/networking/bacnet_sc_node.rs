//! BACnet/SC Node Example
//!
//! This example demonstrates how to use the BACnet Secure Connect (BACnet/SC)
//! implementation to connect to a hub and exchange messages.
//!
//! # Prerequisites
//!
//! Before running this example, you need:
//! 1. A BACnet/SC hub running and accessible
//! 2. Client certificate and private key (PEM format)
//! 3. CA certificate for server verification (PEM format)
//! 4. A unique 6-byte VMAC address for this node
//!
//! # Certificate Generation
//!
//! You can generate test certificates using OpenSSL:
//!
//! ```bash
//! # Generate CA certificate
//! openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes
//!
//! # Generate client certificate
//! openssl req -newkey rsa:4096 -keyout client.key -out client.csr -nodes
//! openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
//! ```
//!
//! # Usage
//!
//! ```bash
//! cargo run --example bacnet_sc_node --features bacnet-sc
//! ```
//!
//! Or with custom parameters:
//!
//! ```bash
//! BSC_HUB_URL="wss://hub.example.com:443" \
//! BSC_CLIENT_CERT="/path/to/client.crt" \
//! BSC_CLIENT_KEY="/path/to/client.key" \
//! BSC_CA_CERT="/path/to/ca.crt" \
//! BSC_VMAC="01:02:03:04:05:06" \
//! cargo run --example bacnet_sc_node --features bacnet-sc
//! ```

use std::env;
use std::time::Duration;

use bacnet_rs::datalink::bsc::{BscClientConfig, BscNode, NodeState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("BACnet/SC Node Example");
    println!("======================\n");

    // Load configuration from environment variables
    let hub_url = env::var("BSC_HUB_URL").unwrap_or_else(|_| "wss://localhost:443".to_string());

    let client_cert_path =
        env::var("BSC_CLIENT_CERT").unwrap_or_else(|_| "certs/client.crt".to_string());

    let client_key_path =
        env::var("BSC_CLIENT_KEY").unwrap_or_else(|_| "certs/client.key".to_string());

    let ca_cert_path = env::var("BSC_CA_CERT").unwrap_or_else(|_| "certs/ca.crt".to_string());

    // Parse VMAC address from string (format: "01:02:03:04:05:06")
    let vmac_str = env::var("BSC_VMAC").unwrap_or_else(|_| "01:02:03:04:05:06".to_string());
    let vmac_address = parse_vmac(&vmac_str)?;

    println!("Configuration:");
    println!("  Hub URL: {}", hub_url);
    println!("  Client Certificate: {}", client_cert_path);
    println!("  Client Key: {}", client_key_path);
    println!("  CA Certificate: {}", ca_cert_path);
    println!(
        "  VMAC Address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}\n",
        vmac_address[0],
        vmac_address[1],
        vmac_address[2],
        vmac_address[3],
        vmac_address[4],
        vmac_address[5]
    );

    // Create client configuration
    let config = BscClientConfig {
        hub_url,
        client_cert_path,
        client_key_path,
        ca_cert_path,
        vmac_address,
        connect_timeout: Duration::from_secs(30),
        heartbeat_interval: Duration::from_secs(60),
        max_message_size: 1500,
    };

    // Create node
    let node = BscNode::new(config);

    // Connect to hub
    println!("Connecting to hub...");
    match node.connect().await {
        Ok(()) => {
            println!("✓ Connected successfully");
            println!("Current state: {:?}\n", node.state().await);
        }
        Err(e) => {
            eprintln!("✗ Connection failed: {}", e);
            return Err(e.into());
        }
    }

    // Start heartbeat task
    println!("Starting heartbeat task...");
    node.start_heartbeat().await;
    println!("✓ Heartbeat task started\n");

    // Send a broadcast Who-Is message
    println!("Sending broadcast Who-Is...");
    let who_is_npdu = create_who_is_npdu();
    match node.send_broadcast_npdu(who_is_npdu).await {
        Ok(()) => println!("✓ Who-Is sent successfully"),
        Err(e) => eprintln!("✗ Failed to send Who-Is: {}", e),
    }

    // Receive messages for 30 seconds
    println!("\nReceiving messages for 30 seconds...");
    println!("Press Ctrl+C to stop\n");

    let start_time = std::time::Instant::now();
    let timeout = Duration::from_secs(30);
    let mut message_count = 0;

    while start_time.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_secs(1), node.receive_message()).await {
            Ok(Ok(message)) => {
                message_count += 1;
                println!("Received message #{}:", message_count);
                println!("  Function: {:?}", message.header.function);
                println!(
                    "  Origin VMAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    message.header.origin_vmac[0],
                    message.header.origin_vmac[1],
                    message.header.origin_vmac[2],
                    message.header.origin_vmac[3],
                    message.header.origin_vmac[4],
                    message.header.origin_vmac[5]
                );
                if let Some(dest) = message.header.destination_vmac {
                    println!(
                        "  Dest VMAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]
                    );
                }
                println!("  Payload size: {} bytes", message.payload.len());
                println!();
            }
            Ok(Err(e)) => {
                eprintln!("Error receiving message: {}", e);
                break;
            }
            Err(_) => {
                // Timeout - continue waiting
            }
        }
    }

    // Disconnect
    println!("\nDisconnecting from hub...");
    match node.disconnect().await {
        Ok(()) => println!("✓ Disconnected successfully"),
        Err(e) => eprintln!("✗ Disconnect failed: {}", e),
    }

    println!("\nTotal messages received: {}", message_count);
    println!("Example completed");

    Ok(())
}

/// Parse VMAC address from string (format: "01:02:03:04:05:06")
fn parse_vmac(vmac_str: &str) -> Result<[u8; 6], Box<dyn std::error::Error>> {
    let parts: Vec<&str> = vmac_str.split(':').collect();
    if parts.len() != 6 {
        return Err("VMAC address must have 6 bytes separated by colons".into());
    }

    let mut vmac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        vmac[i] = u8::from_str_radix(part, 16)?;
    }

    Ok(vmac)
}

/// Create a simple Who-Is NPDU for demonstration
///
/// This is a simplified Who-Is message. In a real application, you would use
/// the service layer to construct proper BACnet messages.
fn create_who_is_npdu() -> Vec<u8> {
    // Simplified NPDU header + APDU
    // NPDU: Version=1, Control=0x20 (no destination), Hopcount=0xFF
    // APDU: Unconfirmed-Request, Service Choice=Who-Is
    vec![
        0x01, // NPDU Version
        0x20, // Control flags (no destination, network layer message not set)
        0x08, // Unconfirmed-Request PDU
        0x00, // Who-Is service choice
    ]
}
