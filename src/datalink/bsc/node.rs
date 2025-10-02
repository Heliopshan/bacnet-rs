//! BACnet/SC Node Implementation
//!
//! Provides high-level node functionality for connecting to BACnet/SC hubs
//! and managing message exchange.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::interval;

use super::bvlc::{BvlcScControl, BvlcScError, BvlcScFunction, BvlcScHeader, BvlcScMessage};
use super::client::{BscClient, BscClientConfig};

/// BACnet/SC node state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Not connected to hub
    Disconnected,

    /// Connecting to hub
    Connecting,

    /// Connected and ready
    Connected,

    /// Connection error
    Error,
}

/// BACnet/SC node
///
/// High-level interface for BACnet/SC communication through a hub.
pub struct BscNode {
    /// Client for WebSocket communication
    client: Arc<Mutex<BscClient>>,

    /// Current node state
    state: Arc<Mutex<NodeState>>,

    /// Heartbeat interval
    heartbeat_interval: Duration,
}

impl BscNode {
    /// Create a new BACnet/SC node
    pub fn new(config: BscClientConfig) -> Self {
        let heartbeat_interval = config.heartbeat_interval;
        let client = BscClient::new(config);

        Self {
            client: Arc::new(Mutex::new(client)),
            state: Arc::new(Mutex::new(NodeState::Disconnected)),
            heartbeat_interval,
        }
    }

    /// Connect to the hub and perform handshake
    pub async fn connect(&self) -> Result<(), BvlcScError> {
        // Update state
        *self.state.lock().await = NodeState::Connecting;

        // Connect WebSocket
        let mut client = self.client.lock().await;
        client.connect().await?;

        // Send connect request
        let vmac = client.vmac_address();
        let connect_request = self.create_connect_request(vmac);
        client.send_message(&connect_request).await?;

        // Wait for connect accept
        let response = client.receive_message().await?;
        if response.header.function != BvlcScFunction::ConnectAccept {
            *self.state.lock().await = NodeState::Error;
            return Err(BvlcScError::ConnectionError(
                "Expected ConnectAccept, got different response".to_string(),
            ));
        }

        // Update state
        *self.state.lock().await = NodeState::Connected;

        Ok(())
    }

    /// Disconnect from the hub
    pub async fn disconnect(&self) -> Result<(), BvlcScError> {
        let mut client = self.client.lock().await;

        if client.is_connected() {
            // Send disconnect request
            let vmac = client.vmac_address();
            let disconnect_request = self.create_disconnect_request(vmac);
            let _ = client.send_message(&disconnect_request).await;

            // Close connection
            client.disconnect().await?;
        }

        *self.state.lock().await = NodeState::Disconnected;
        Ok(())
    }

    /// Send an encapsulated NPDU to a destination
    pub async fn send_npdu(
        &self,
        destination_vmac: [u8; 6],
        npdu_data: Vec<u8>,
    ) -> Result<(), BvlcScError> {
        let client = self.client.lock().await;
        let vmac = client.vmac_address();

        let control = BvlcScControl {
            originating_message: true,
            destination_options: false,
            data_options: false,
            destination_broadcast: false,
        };

        let header = BvlcScHeader::new(
            BvlcScFunction::EncapsulatedNpdu,
            control,
            vmac,
            Some(destination_vmac),
        );

        let message = BvlcScMessage::new(header, npdu_data);

        drop(client);
        self.client.lock().await.send_message(&message).await
    }

    /// Send a broadcast NPDU
    pub async fn send_broadcast_npdu(&self, npdu_data: Vec<u8>) -> Result<(), BvlcScError> {
        let client = self.client.lock().await;
        let vmac = client.vmac_address();

        let control = BvlcScControl {
            originating_message: true,
            destination_options: false,
            data_options: false,
            destination_broadcast: true,
        };

        let header = BvlcScHeader::new(BvlcScFunction::EncapsulatedNpdu, control, vmac, None);

        let message = BvlcScMessage::new(header, npdu_data);

        drop(client);
        self.client.lock().await.send_message(&message).await
    }

    /// Receive a message from the hub
    pub async fn receive_message(&self) -> Result<BvlcScMessage, BvlcScError> {
        self.client.lock().await.receive_message().await
    }

    /// Start heartbeat task
    ///
    /// Spawns a background task that sends periodic heartbeat messages
    /// to keep the connection alive.
    pub async fn start_heartbeat(&self) {
        let client = Arc::clone(&self.client);
        let state = Arc::clone(&self.state);
        let heartbeat_interval = self.heartbeat_interval;

        tokio::spawn(async move {
            let mut interval_timer = interval(heartbeat_interval);

            loop {
                interval_timer.tick().await;

                // Check if connected
                let current_state = *state.lock().await;
                if current_state != NodeState::Connected {
                    break;
                }

                // Send heartbeat
                let mut client_lock = client.lock().await;
                let vmac = client_lock.vmac_address();

                let control = BvlcScControl {
                    originating_message: true,
                    destination_options: false,
                    data_options: false,
                    destination_broadcast: false,
                };

                let header =
                    BvlcScHeader::new(BvlcScFunction::HeartbeatRequest, control, vmac, None);

                let heartbeat = BvlcScMessage::new(header, vec![]);

                if let Err(e) = client_lock.send_message(&heartbeat).await {
                    log::error!("Heartbeat failed: {}", e);
                    *state.lock().await = NodeState::Error;
                    break;
                }
            }
        });
    }

    /// Get the current node state
    pub async fn state(&self) -> NodeState {
        *self.state.lock().await
    }

    /// Create a connect request message
    fn create_connect_request(&self, vmac: [u8; 6]) -> BvlcScMessage {
        let control = BvlcScControl {
            originating_message: true,
            destination_options: false,
            data_options: false,
            destination_broadcast: false,
        };

        let header = BvlcScHeader::new(BvlcScFunction::ConnectRequest, control, vmac, None);

        // Payload contains max BVLL and NPDU sizes (both 2 bytes, big-endian)
        let max_bvll_size = 1500u16;
        let max_npdu_size = 1497u16; // BVLL size - 3 bytes header overhead

        let mut payload = Vec::with_capacity(4);
        payload.extend_from_slice(&max_bvll_size.to_be_bytes());
        payload.extend_from_slice(&max_npdu_size.to_be_bytes());

        BvlcScMessage::new(header, payload)
    }

    /// Create a disconnect request message
    fn create_disconnect_request(&self, vmac: [u8; 6]) -> BvlcScMessage {
        let control = BvlcScControl {
            originating_message: true,
            destination_options: false,
            data_options: false,
            destination_broadcast: false,
        };

        let header = BvlcScHeader::new(BvlcScFunction::DisconnectRequest, control, vmac, None);

        BvlcScMessage::new(header, vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_creation() {
        let config = BscClientConfig {
            hub_url: "wss://hub.example.com".to_string(),
            vmac_address: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            ..Default::default()
        };

        let node = BscNode::new(config);
        // Node created successfully
    }

    #[tokio::test]
    async fn test_node_initial_state() {
        let config = BscClientConfig {
            hub_url: "wss://hub.example.com".to_string(),
            vmac_address: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            ..Default::default()
        };

        let node = BscNode::new(config);
        assert_eq!(node.state().await, NodeState::Disconnected);
    }
}
