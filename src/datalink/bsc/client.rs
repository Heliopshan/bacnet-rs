//! BACnet/SC WebSocket Client with TLS Support
//!
//! Provides secure WebSocket connections to BACnet/SC hubs using
//! TLS with mutual certificate authentication.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async_tls_with_config, tungstenite::protocol::WebSocketConfig, Connector,
    MaybeTlsStream, WebSocketStream,
};
use url::Url;

use super::bvlc::{BvlcScError, BvlcScMessage};

/// BACnet/SC WebSocket subprotocol for hub connections
pub const SUBPROTOCOL_HUB: &str = "hub.bsc.bacnet.org";

/// BACnet/SC WebSocket subprotocol for direct connections
pub const SUBPROTOCOL_DIRECT: &str = "dc.bsc.bacnet.org";

/// Default WebSocket connection timeout (30 seconds)
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default heartbeat interval (60 seconds)
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// BACnet/SC client configuration
#[derive(Debug, Clone)]
pub struct BscClientConfig {
    /// Hub WebSocket URL (e.g., "wss://hub.example.com:443")
    pub hub_url: String,

    /// Path to client certificate file (PEM format)
    pub client_cert_path: String,

    /// Path to client private key file (PEM format)
    pub client_key_path: String,

    /// Path to CA certificate file for server verification (PEM format)
    pub ca_cert_path: String,

    /// Virtual MAC address for this node (6 bytes)
    pub vmac_address: [u8; 6],

    /// Connection timeout
    pub connect_timeout: Duration,

    /// Heartbeat interval
    pub heartbeat_interval: Duration,

    /// Maximum message size (bytes)
    pub max_message_size: usize,
}

impl Default for BscClientConfig {
    fn default() -> Self {
        Self {
            hub_url: String::new(),
            client_cert_path: String::new(),
            client_key_path: String::new(),
            ca_cert_path: String::new(),
            vmac_address: [0; 6],
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            max_message_size: 1500, // Standard Ethernet MTU
        }
    }
}

/// BACnet/SC WebSocket client
pub struct BscClient {
    /// Client configuration
    config: BscClientConfig,

    /// WebSocket connection
    ws_stream: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
}

impl BscClient {
    /// Create a new BACnet/SC client
    pub fn new(config: BscClientConfig) -> Self {
        Self {
            config,
            ws_stream: None,
        }
    }

    /// Connect to the BACnet/SC hub
    pub async fn connect(&mut self) -> Result<(), BvlcScError> {
        // Parse the hub URL
        let url = Url::parse(&self.config.hub_url)
            .map_err(|e| BvlcScError::ConnectionError(format!("Invalid hub URL: {}", e)))?;

        // Load TLS certificates
        let tls_connector = self.create_tls_connector()?;

        // Configure WebSocket
        let ws_config = WebSocketConfig {
            max_message_size: Some(self.config.max_message_size),
            max_frame_size: Some(self.config.max_message_size),
            ..Default::default()
        };

        // Create request with BACnet/SC subprotocol
        let request = tungstenite::handshake::client::Request::builder()
            .uri(url.as_str())
            .header("Sec-WebSocket-Protocol", SUBPROTOCOL_HUB)
            .body(())
            .map_err(|e| {
                BvlcScError::ConnectionError(format!("Failed to create request: {}", e))
            })?;

        // Connect with TLS
        let (ws_stream, _response) = connect_async_tls_with_config(
            request,
            Some(ws_config),
            false,
            Some(Connector::NativeTls(tls_connector)),
        )
        .await
        .map_err(|e| BvlcScError::ConnectionError(format!("Connection failed: {}", e)))?;

        self.ws_stream = Some(ws_stream);

        Ok(())
    }

    /// Create TLS connector with mutual authentication
    fn create_tls_connector(&self) -> Result<native_tls::TlsConnector, BvlcScError> {
        use std::fs::File;
        use std::io::Read;

        // Load client certificate
        let mut cert_file = File::open(&self.config.client_cert_path).map_err(|e| {
            BvlcScError::ConnectionError(format!("Failed to open client cert: {}", e))
        })?;
        let mut cert_pem = Vec::new();
        cert_file.read_to_end(&mut cert_pem).map_err(|e| {
            BvlcScError::ConnectionError(format!("Failed to read client cert: {}", e))
        })?;

        // Load client private key
        let mut key_file = File::open(&self.config.client_key_path).map_err(|e| {
            BvlcScError::ConnectionError(format!("Failed to open client key: {}", e))
        })?;
        let mut key_pem = Vec::new();
        key_file.read_to_end(&mut key_pem).map_err(|e| {
            BvlcScError::ConnectionError(format!("Failed to read client key: {}", e))
        })?;

        // Create identity from certificate and key
        let identity = native_tls::Identity::from_pkcs8(&cert_pem, &key_pem).map_err(|e| {
            BvlcScError::ConnectionError(format!("Failed to create identity: {}", e))
        })?;

        // Load CA certificate for server verification
        let mut ca_file = File::open(&self.config.ca_cert_path)
            .map_err(|e| BvlcScError::ConnectionError(format!("Failed to open CA cert: {}", e)))?;
        let mut ca_pem = Vec::new();
        ca_file
            .read_to_end(&mut ca_pem)
            .map_err(|e| BvlcScError::ConnectionError(format!("Failed to read CA cert: {}", e)))?;

        let ca_cert = native_tls::Certificate::from_pem(&ca_pem)
            .map_err(|e| BvlcScError::ConnectionError(format!("Failed to parse CA cert: {}", e)))?;

        // Build TLS connector with mutual authentication
        let connector = native_tls::TlsConnector::builder()
            .identity(identity)
            .add_root_certificate(ca_cert)
            .build()
            .map_err(|e| {
                BvlcScError::ConnectionError(format!("Failed to build TLS connector: {}", e))
            })?;

        Ok(connector)
    }

    /// Send a BVLC-SC message
    pub async fn send_message(&mut self, message: &BvlcScMessage) -> Result<(), BvlcScError> {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let ws_stream = self
            .ws_stream
            .as_mut()
            .ok_or_else(|| BvlcScError::ConnectionError("Not connected".to_string()))?;

        let encoded = message.encode();
        let ws_message = Message::Binary(encoded.to_vec());

        ws_stream
            .send(ws_message)
            .await
            .map_err(|e| BvlcScError::ConnectionError(format!("Send failed: {}", e)))?;

        Ok(())
    }

    /// Receive a BVLC-SC message
    pub async fn receive_message(&mut self) -> Result<BvlcScMessage, BvlcScError> {
        use bytes::Bytes;
        use tokio_tungstenite::tungstenite::Message;

        let ws_stream = self
            .ws_stream
            .as_mut()
            .ok_or_else(|| BvlcScError::ConnectionError("Not connected".to_string()))?;

        use futures_util::StreamExt;
        let ws_message = ws_stream
            .next()
            .await
            .ok_or_else(|| BvlcScError::ConnectionError("Connection closed".to_string()))?
            .map_err(|e| BvlcScError::ConnectionError(format!("Receive failed: {}", e)))?;

        match ws_message {
            Message::Binary(data) => {
                let bytes = Bytes::from(data);
                BvlcScMessage::decode(bytes)
            }
            Message::Close(_) => Err(BvlcScError::ConnectionError(
                "Connection closed".to_string(),
            )),
            _ => Err(BvlcScError::ConnectionError(
                "Unexpected message type".to_string(),
            )),
        }
    }

    /// Disconnect from the hub
    pub async fn disconnect(&mut self) -> Result<(), BvlcScError> {
        #[allow(unused_imports)]
        use futures_util::SinkExt;

        if let Some(mut ws_stream) = self.ws_stream.take() {
            ws_stream
                .close(None)
                .await
                .map_err(|e| BvlcScError::ConnectionError(format!("Disconnect failed: {}", e)))?;
        }
        Ok(())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.ws_stream.is_some()
    }

    /// Get the client's VMAC address
    pub fn vmac_address(&self) -> [u8; 6] {
        self.config.vmac_address
    }
}
