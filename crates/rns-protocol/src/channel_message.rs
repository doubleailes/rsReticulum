/// Base trait for channel messages.
///
/// All channel messages must define a MSGTYPE (< 0xF000 for user messages),
/// and implement pack/unpack for serialization.
pub trait MessageBase: Send {
    /// Unique message type identifier.
    /// Must be < 0xF000 for user messages, >= 0xF000 for system messages.
    fn msg_type(&self) -> u16;

    /// Serialize the message payload.
    fn pack(&self) -> Vec<u8>;

    /// Deserialize from raw bytes.
    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError>;
}

/// Reserved message type namespace for system messages.
pub const SYSTEM_MESSAGE_TYPE_MIN: u16 = 0xF000;

/// System message type for stream data (Buffer).
pub const SMT_STREAM_DATA: u16 = 0xFF00;

/// Message lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageState {
    New,
    Sent,
    Delivered,
    Failed,
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelMessageError {
    #[error("message unpack failed")]
    UnpackFailed,
    #[error("invalid message type")]
    InvalidType,
    #[error("message too short")]
    TooShort,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_message_range() {
        const { assert!(SMT_STREAM_DATA >= SYSTEM_MESSAGE_TYPE_MIN) };
    }
}
