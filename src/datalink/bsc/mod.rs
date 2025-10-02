//! BACnet/SC (Secure Connect) Implementation
//!
//! Implements ASHRAE 135-2020 Addendum bj (Annex AB) - BACnet Secure Connect.
//!
//! BACnet/SC provides secure, WebSocket-based communication for BACnet networks with:
//! - TLS encryption with mutual certificate authentication
//! - Hub-and-spoke topology for centralized routing
//! - Virtual MAC (VMAC) addressing
//! - Support for both direct and hub-routed connections
//!
//! # Architecture
//!
//! BACnet/SC uses a hub-and-spoke architecture where:
//! - **Nodes** are BACnet devices that connect to one or more hubs
//! - **Hubs** provide routing and message forwarding between nodes
//! - Communication uses WebSocket over TLS (WSS)
//! - Each node has a unique 6-byte Virtual MAC (VMAC) address
//!
//! # Security
//!
//! BACnet/SC requires:
//! - TLS 1.2 or higher
//! - Cipher suite: `TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8` (RFC 7251)
//! - Mutual authentication using X.509 certificates
//! - Certificate-based access control at the hub
//!
//! # Usage
//!
//! ```rust,ignore
//! use bacnet_rs::datalink::bsc::{BscClientConfig, BscNode};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure the client
//!     let config = BscClientConfig {
//!         hub_url: "wss://hub.example.com:443".to_string(),
//!         client_cert_path: "/path/to/client.crt".to_string(),
//!         client_key_path: "/path/to/client.key".to_string(),
//!         ca_cert_path: "/path/to/ca.crt".to_string(),
//!         vmac_address: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
//!         ..Default::default()
//!     };
//!
//!     // Create and connect node
//!     let node = BscNode::new(config);
//!     node.connect().await?;
//!
//!     // Start heartbeat
//!     node.start_heartbeat().await;
//!
//!     // Send a broadcast Who-Is
//!     let npdu_data = vec![/* NPDU bytes */];
//!     node.send_broadcast_npdu(npdu_data).await?;
//!
//!     // Receive messages
//!     loop {
//!         let message = node.receive_message().await?;
//!         // Process message
//!     }
//! }
//! ```
//!
//! # Message Flow
//!
//! 1. **Connection**: Node connects to hub via WSS with mutual TLS auth
//! 2. **Handshake**: Node sends ConnectRequest, hub responds with ConnectAccept
//! 3. **Communication**: Nodes exchange EncapsulatedNPDU messages via hub
//! 4. **Heartbeat**: Periodic HeartbeatRequest/HeartbeatAck to maintain connection
//! 5. **Disconnection**: Node sends DisconnectRequest, hub responds with DisconnectAck
//!
//! # Protocol Details
//!
//! BVLC-SC messages have the following header structure:
//!
//! ```text
//! +--------+----------+---------------+----------+--------------+------------------+
//! | Byte 0 | Byte 1   | Bytes 2-3     | Byte 4   | Bytes 5-10   | Bytes 11-16      |
//! +--------+----------+---------------+----------+--------------+------------------+
//! | 0x82   | Function | Message Len   | Control  | Origin VMAC  | Dest VMAC (opt)  |
//! +--------+----------+---------------+----------+--------------+------------------+
//! ```
//!
//! # WebSocket Subprotocols
//!
//! - `hub.bsc.bacnet.org` - For node-to-hub connections
//! - `dc.bsc.bacnet.org` - For direct node-to-node connections
//!
//! # References
//!
//! - ASHRAE 135-2020, Addendum bj (Annex AB): BACnet Secure Connect
//! - RFC 7251: AES-CCM Cipher Suites for TLS
//! - RFC 6455: The WebSocket Protocol

pub mod bvlc;
pub mod client;
pub mod node;

pub use bvlc::{
    BvlcScControl, BvlcScError, BvlcScFunction, BvlcScHeader, BvlcScMessage, BvlcScResultCode,
};
pub use client::{BscClient, BscClientConfig, SUBPROTOCOL_DIRECT, SUBPROTOCOL_HUB};
pub use node::{BscNode, NodeState};
