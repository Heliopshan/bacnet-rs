//! BVLC-SC (BACnet Virtual Link Control - Secure Connect) Protocol
//!
//! Implements ASHRAE 135-2020 Addendum bj (Annex AB) - BACnet Secure Connect
//!
//! BVLC-SC provides secure WebSocket-based communication for BACnet networks
//! with TLS encryption and certificate-based authentication.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// BVLC-SC message type identifier (1 byte)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BvlcScFunction {
    /// BVLC-Result: Response indicating success or failure
    BvlcResult = 0x00,

    /// Encapsulated NPDU
    EncapsulatedNpdu = 0x01,

    /// Address Resolution request
    AddressResolution = 0x02,

    /// Address Resolution ACK
    AddressResolutionAck = 0x03,

    /// Advertisement: Hub announces its presence
    Advertisement = 0x04,

    /// Advertisement Solicitation: Request hub advertisement
    AdvertisementSolicitation = 0x05,

    /// Connect Request: Node requests connection to hub
    ConnectRequest = 0x06,

    /// Connect Accept: Hub accepts connection
    ConnectAccept = 0x07,

    /// Disconnect Request: Graceful disconnection
    DisconnectRequest = 0x08,

    /// Disconnect ACK: Confirms disconnection
    DisconnectAck = 0x09,

    /// Heartbeat Request: Keep-alive message
    HeartbeatRequest = 0x0A,

    /// Heartbeat ACK: Response to heartbeat
    HeartbeatAck = 0x0B,

    /// Proprietary Message
    ProprietaryMessage = 0x0C,
}

impl BvlcScFunction {
    /// Convert from u8, returns None for unknown values
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::BvlcResult),
            0x01 => Some(Self::EncapsulatedNpdu),
            0x02 => Some(Self::AddressResolution),
            0x03 => Some(Self::AddressResolutionAck),
            0x04 => Some(Self::Advertisement),
            0x05 => Some(Self::AdvertisementSolicitation),
            0x06 => Some(Self::ConnectRequest),
            0x07 => Some(Self::ConnectAccept),
            0x08 => Some(Self::DisconnectRequest),
            0x09 => Some(Self::DisconnectAck),
            0x0A => Some(Self::HeartbeatRequest),
            0x0B => Some(Self::HeartbeatAck),
            0x0C => Some(Self::ProprietaryMessage),
            _ => None,
        }
    }
}

/// BVLC-SC result codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum BvlcScResultCode {
    /// Successful completion
    Success = 0x0000,

    /// Address resolution failure
    AddressResolutionNak = 0x0030,

    /// VMAC address already in use
    VmacAddressInUse = 0x0040,

    /// Connection request rejected
    ConnectRequestRejected = 0x0050,

    /// Disconnect requested by other party
    DisconnectOther = 0x0060,

    /// Disconnect due to errors
    DisconnectErrors = 0x0070,

    /// Malformed message
    MessageMalformed = 0x0080,
}

/// BVLC-SC header control flags (1 byte)
#[derive(Debug, Clone, Copy, Default)]
pub struct BvlcScControl {
    /// Message is originated by the sending node (not forwarded)
    pub originating_message: bool,

    /// Destination options present
    pub destination_options: bool,

    /// Data options present
    pub data_options: bool,

    /// Destination is a broadcast VMAC
    pub destination_broadcast: bool,
}

impl BvlcScControl {
    /// Encode control byte
    pub fn encode(&self) -> u8 {
        let mut byte = 0u8;
        if self.originating_message {
            byte |= 0x01;
        }
        if self.destination_options {
            byte |= 0x02;
        }
        if self.data_options {
            byte |= 0x04;
        }
        if self.destination_broadcast {
            byte |= 0x08;
        }
        byte
    }

    /// Decode control byte
    pub fn decode(byte: u8) -> Self {
        Self {
            originating_message: (byte & 0x01) != 0,
            destination_options: (byte & 0x02) != 0,
            data_options: (byte & 0x04) != 0,
            destination_broadcast: (byte & 0x08) != 0,
        }
    }
}

/// BVLC-SC message header
///
/// Header format (minimum 8 bytes):
/// - Byte 0: BVLC Type (0x82 for BVLC-SC)
/// - Byte 1: Function
/// - Bytes 2-3: Message Length (including header)
/// - Byte 4: Control flags
/// - Bytes 5-6: Origin VMAC (first 2 bytes, remaining 4 bytes follow)
/// - Bytes 7-10: Origin VMAC (last 4 bytes)
/// - Bytes 11-16: Destination VMAC (if not broadcast)
/// - Variable: Destination options (if present)
/// - Variable: Data options (if present)
/// - Variable: Payload
#[derive(Debug, Clone)]
pub struct BvlcScHeader {
    /// BVLC function code
    pub function: BvlcScFunction,

    /// Message length (including header)
    pub message_length: u16,

    /// Control flags
    pub control: BvlcScControl,

    /// Origin Virtual MAC address (6 bytes)
    pub origin_vmac: [u8; 6],

    /// Destination Virtual MAC address (6 bytes, optional)
    pub destination_vmac: Option<[u8; 6]>,
}

impl BvlcScHeader {
    /// BVLC Type identifier for BVLC-SC
    pub const BVLC_TYPE: u8 = 0x82;

    /// Minimum header size (without destination VMAC)
    pub const MIN_HEADER_SIZE: usize = 11;

    /// Maximum header size (with destination VMAC, no options)
    pub const MAX_BASIC_HEADER_SIZE: usize = 17;

    /// Create a new BVLC-SC header
    pub fn new(
        function: BvlcScFunction,
        control: BvlcScControl,
        origin_vmac: [u8; 6],
        destination_vmac: Option<[u8; 6]>,
    ) -> Self {
        let header_size = if destination_vmac.is_some() { 17 } else { 11 };
        Self {
            function,
            message_length: header_size as u16,
            control,
            origin_vmac,
            destination_vmac,
        }
    }

    /// Encode header to bytes
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.message_length as usize);

        // BVLC Type
        buf.put_u8(Self::BVLC_TYPE);

        // Function
        buf.put_u8(self.function as u8);

        // Message Length
        buf.put_u16(self.message_length);

        // Control flags
        buf.put_u8(self.control.encode());

        // Origin VMAC (6 bytes)
        buf.put_slice(&self.origin_vmac);

        // Destination VMAC (6 bytes, if not broadcast)
        if let Some(dest_vmac) = self.destination_vmac {
            buf.put_slice(&dest_vmac);
        }

        buf
    }

    /// Decode header from bytes
    pub fn decode(buf: &mut Bytes) -> Result<Self, BvlcScError> {
        if buf.len() < Self::MIN_HEADER_SIZE {
            return Err(BvlcScError::MessageTooShort);
        }

        // Check BVLC Type
        let bvlc_type = buf.get_u8();
        if bvlc_type != Self::BVLC_TYPE {
            return Err(BvlcScError::InvalidBvlcType(bvlc_type));
        }

        // Function
        let function_byte = buf.get_u8();
        let function = BvlcScFunction::from_u8(function_byte)
            .ok_or(BvlcScError::UnknownFunction(function_byte))?;

        // Message Length
        let message_length = buf.get_u16();

        // Control flags
        let control = BvlcScControl::decode(buf.get_u8());

        // Origin VMAC (6 bytes)
        let mut origin_vmac = [0u8; 6];
        buf.copy_to_slice(&mut origin_vmac);

        // Destination VMAC (6 bytes, if not broadcast)
        let destination_vmac = if !control.destination_broadcast && buf.len() >= 6 {
            let mut dest_vmac = [0u8; 6];
            buf.copy_to_slice(&mut dest_vmac);
            Some(dest_vmac)
        } else {
            None
        };

        Ok(Self {
            function,
            message_length,
            control,
            origin_vmac,
            destination_vmac,
        })
    }
}

/// BVLC-SC message
#[derive(Debug, Clone)]
pub struct BvlcScMessage {
    /// Message header
    pub header: BvlcScHeader,

    /// Message payload
    pub payload: Vec<u8>,
}

impl BvlcScMessage {
    /// Create a new BVLC-SC message
    pub fn new(header: BvlcScHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Encode message to bytes
    pub fn encode(&self) -> BytesMut {
        let mut buf = self.header.encode();
        buf.put_slice(&self.payload);
        buf
    }

    /// Decode message from bytes
    pub fn decode(mut buf: Bytes) -> Result<Self, BvlcScError> {
        let header = BvlcScHeader::decode(&mut buf)?;
        let payload = buf.to_vec();
        Ok(Self { header, payload })
    }
}

/// BVLC-SC errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BvlcScError {
    /// Message too short to contain valid header
    MessageTooShort,

    /// Invalid BVLC type byte
    InvalidBvlcType(u8),

    /// Unknown function code
    UnknownFunction(u8),

    /// Invalid message length
    InvalidLength,

    /// Connection error
    ConnectionError(
        #[cfg(feature = "std")] String,
        #[cfg(not(feature = "std"))] &'static str,
    ),
}

#[cfg(feature = "std")]
impl std::fmt::Display for BvlcScError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessageTooShort => write!(f, "BVLC-SC message too short"),
            Self::InvalidBvlcType(t) => write!(f, "Invalid BVLC type: 0x{:02X}", t),
            Self::UnknownFunction(func) => write!(f, "Unknown BVLC-SC function: 0x{:02X}", func),
            Self::InvalidLength => write!(f, "Invalid message length"),
            Self::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BvlcScError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_encode_decode() {
        let control = BvlcScControl {
            originating_message: true,
            destination_options: false,
            data_options: true,
            destination_broadcast: false,
        };

        let encoded = control.encode();
        assert_eq!(encoded, 0x05); // 0x01 | 0x04

        let decoded = BvlcScControl::decode(encoded);
        assert_eq!(decoded.originating_message, true);
        assert_eq!(decoded.destination_options, false);
        assert_eq!(decoded.data_options, true);
        assert_eq!(decoded.destination_broadcast, false);
    }

    #[test]
    fn test_header_encode_decode() {
        let origin_vmac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let dest_vmac = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

        let control = BvlcScControl {
            originating_message: true,
            destination_options: false,
            data_options: false,
            destination_broadcast: false,
        };

        let header = BvlcScHeader::new(
            BvlcScFunction::EncapsulatedNpdu,
            control,
            origin_vmac,
            Some(dest_vmac),
        );

        let encoded = header.encode();
        let mut bytes = encoded.freeze();
        let decoded = BvlcScHeader::decode(&mut bytes).unwrap();

        assert_eq!(decoded.function, BvlcScFunction::EncapsulatedNpdu);
        assert_eq!(decoded.origin_vmac, origin_vmac);
        assert_eq!(decoded.destination_vmac, Some(dest_vmac));
    }
}
