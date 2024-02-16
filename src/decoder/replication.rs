use std::fmt::Display;

use byteorder::{BigEndian, ByteOrder};
use thiserror::Error;

use super::ReplicationType;

#[derive(Debug)]
pub struct XLogDataBody {
    pub start: i64,
    pub current: i64,
    pub timestamp: i64,
    pub message: ReplicationMessage,
}

impl Display for XLogDataBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "  XLogData: start = {}, current = {}, timestamp = {}",
            self.start, self.current, self.timestamp
        )?;
        writeln!(f, "{}", self.message)
    }
}

#[derive(Error, Debug)]
pub enum XLogDataBodyParseError {
    #[error("invalid message length {0}. It can't be smaller than {1}")]
    LengthTooShort(usize, usize),
}

impl XLogDataBody {
    pub fn parse(
        buf: &[u8],
        replication_type: ReplicationType,
    ) -> Result<XLogDataBody, XLogDataBodyParseError> {
        if buf.len() < 24 {
            return Err(XLogDataBodyParseError::LengthTooShort(buf.len(), 24));
        }
        let start = BigEndian::read_i64(&buf[0..8]);
        let current = BigEndian::read_i64(&buf[8..16]);
        let timestamp = BigEndian::read_i64(&buf[16..24]);

        let message = match replication_type {
            ReplicationType::Logical => ReplicationMessage::Logical(LogicalMessage {
                data: buf[24..].to_vec(),
            }),
            ReplicationType::Physical => ReplicationMessage::Physical(PhysicalMessage {
                data: buf[24..].to_vec(),
            }),
        };

        Ok(XLogDataBody {
            start,
            current,
            timestamp,
            message,
        })
    }
}

#[derive(Debug)]
pub enum ReplicationMessage {
    Physical(PhysicalMessage),
    Logical(LogicalMessage),
}

impl Display for ReplicationMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplicationMessage::Physical(msg) => {
                writeln!(f, "  PhysicalMessage: data={:?}", msg.data)
            }
            ReplicationMessage::Logical(msg) => {
                writeln!(f, "  LogicalMessage: data={:?}", msg.data)
            }
        }
    }
}

// #[derive(Debug)]
// pub enum LogicalMessage {
//     // Begin,
//     // Message,
//     // Commit,
//     // Origin,
//     // Relation,
//     // Type,
//     // Insert,
//     // Update,
//     // Delete,
//     // Truncate,
//     // StreamStart,
//     // StreamStop,
//     // StreamCommit,
//     // StreamAbort,
//     // BeginPrepare,
//     // Prepare,
//     // CommitPrepared,
//     // RollbackPrepared,
//     // StreamPrepare,
// }

#[derive(Debug)]
pub struct LogicalMessage {
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct PhysicalMessage {
    pub data: Vec<u8>,
}

// #[derive(Debug)]
// pub struct TupleData {}

#[derive(Debug)]
pub struct PrimaryKeepaliveBody {
    pub end: i64,
    pub timestamp: i64,
    pub reply_asap: u8,
}

impl Display for PrimaryKeepaliveBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "  PrimaryKeepalive: end = {}, timestamp = {}, reply_asap = {}",
            self.end, self.timestamp, self.reply_asap
        )
    }
}

#[derive(Error, Debug)]
pub enum PrimaryKeepaliveBodyParseError {
    #[error("invalid message length {0}. It can't be smaller than {1}")]
    LengthTooShort(usize, usize),
}

impl PrimaryKeepaliveBody {
    pub fn parse(buf: &[u8]) -> Result<PrimaryKeepaliveBody, PrimaryKeepaliveBodyParseError> {
        if buf.len() < 17 {
            return Err(PrimaryKeepaliveBodyParseError::LengthTooShort(
                buf.len(),
                17,
            ));
        }
        let end = BigEndian::read_i64(&buf[0..8]);
        let timestamp = BigEndian::read_i64(&buf[8..16]);
        let reply_asap = buf[16];

        Ok(PrimaryKeepaliveBody {
            end,
            timestamp,
            reply_asap,
        })
    }
}

// #[derive(Debug)]
// pub struct StandbyStatusUpdateBody {}

// #[derive(Debug)]
// pub struct HotStandbyFeedbackBody {}
