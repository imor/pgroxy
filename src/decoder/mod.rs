pub mod client;
pub mod replication;
pub mod server;

use std::{
    ffi::CStr,
    fmt::Display,
    sync::{Arc, Mutex},
};

use byteorder::{BigEndian, ByteOrder};
use thiserror::Error;

use self::replication::{
    PrimaryKeepaliveBody, PrimaryKeepaliveBodyParseError, XLogDataBody, XLogDataBodyParseError,
};

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub tag: u8,
    pub length: i32,
}

const NUM_HEADER_BYTES: usize = 5;
const NUM_LENGTH_BYTES: usize = 4;

impl Header {
    /// Parses a `Header` from the passed `buf`.
    /// Returns `None` if `buf` doesn't contain enough bytes to parse a full message.
    ///
    /// # Panics
    ///
    /// panics if the header length is less than 4.
    fn parse(buf: &[u8]) -> Option<Header> {
        if buf.len() < NUM_HEADER_BYTES {
            return None;
        }

        // First byte contains the tag
        let tag = buf[0];

        // Bytes 1 to 4 contain the length of the message.
        let length = BigEndian::read_i32(&buf[1..NUM_HEADER_BYTES]);

        // Can't do much here other than panicking. Invalid length is a fatal protocol violation.
        if length < NUM_LENGTH_BYTES as i32 {
            panic!("invalid header length {length}. It should be greater than 4");
        }

        // Length of a full message including the header
        let full_message_length = length as usize + 1;

        // If there's not enough data in the buffer to parse a full message, wait
        if buf.len() < full_message_length {
            return None;
        }

        Some(Header { tag, length })
    }

    /// Returns the length of the message including the header
    fn msg_length(&self) -> usize {
        self.length as usize + 1
    }

    /// Returns the length of the message excluding the header
    fn payload_length(&self) -> usize {
        self.length as usize - 4
    }
}

#[derive(Debug)]
pub struct CopyDataBody {
    pub contents: CopyDataBodyContents,
}

#[derive(Error, Debug)]
pub enum CopyDataBodyParseError {
    #[error("invalid copy data body contents: {0}")]
    InvalidContents(#[from] CopyDataBodyContentsParseError),
}

impl Display for CopyDataBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: CopyData")?;
        write!(f, "{}", self.contents)
    }
}

impl CopyDataBody {
    fn parse(
        buf: &[u8],
        replication_type: Option<ReplicationType>,
    ) -> Result<CopyDataBody, CopyDataBodyParseError> {
        let contents = CopyDataBodyContents::parse(buf, replication_type)?;
        Ok(CopyDataBody { contents })
    }
}

#[derive(Debug)]
pub enum CopyDataBodyContents {
    XLogData(XLogDataBody),
    PrimaryKeepalive(PrimaryKeepaliveBody),
    // StandbyStatusUpdate(StandbyStatusUpdateBody),
    // HotStandbyFeedback(HotStandbyFeedbackBody),
    Raw(char, Vec<u8>),
}

impl Display for CopyDataBodyContents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CopyDataBodyContents::XLogData(data) => {
                write!(f, "{}", data)
            }
            CopyDataBodyContents::Raw(tag, data) => {
                writeln!(f, "  Tag: {tag}")?;
                writeln!(f, "  RawData: {data:?}")
            }
            CopyDataBodyContents::PrimaryKeepalive(msg) => {
                write!(f, "{}", msg)
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum CopyDataBodyContentsParseError {
    #[error("invalid message length {0}. It can't be smaller than {1}")]
    LengthTooShort(usize, usize),

    #[error("XLogData message while not replicating")]
    UnexpectedXLogData,

    #[error("XLogData parse error")]
    XLogDataParseError(#[from] XLogDataBodyParseError),

    #[error("PrimaryKeepalive parse error")]
    PrimaryKeepaliveError(#[from] PrimaryKeepaliveBodyParseError),
}

const XLOG_DATA_MESSAGE_TAG: u8 = b'w';
const PRIMARY_KEEPALIVE_MESSAGE_TAG: u8 = b'k';

impl CopyDataBodyContents {
    fn parse(
        buf: &[u8],
        replication_type: Option<ReplicationType>,
    ) -> Result<CopyDataBodyContents, CopyDataBodyContentsParseError> {
        if buf.is_empty() {
            return Err(CopyDataBodyContentsParseError::LengthTooShort(buf.len(), 1));
        }

        let tag = buf[0];
        match tag {
            XLOG_DATA_MESSAGE_TAG => {
                let Some(replication_type) = replication_type else {
                    return Err(CopyDataBodyContentsParseError::UnexpectedXLogData);
                };

                Ok(CopyDataBodyContents::XLogData(XLogDataBody::parse(
                    &buf[1..],
                    replication_type,
                )?))
            }
            PRIMARY_KEEPALIVE_MESSAGE_TAG => Ok(CopyDataBodyContents::PrimaryKeepalive(
                PrimaryKeepaliveBody::parse(&buf[1..])?,
            )),
            tag => Ok(CopyDataBodyContents::Raw(tag as char, buf[1..].to_vec())),
        }
    }
}

#[derive(Debug)]
pub struct CopyDoneBody;

impl Display for CopyDoneBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: CopyDone")
    }
}

#[derive(Error, Debug)]
enum CopyDoneBodyParseError {
    #[error("invalid message length {0}. It should be {1}")]
    InvalidLength(usize, usize),
}

impl CopyDoneBody {
    fn parse(buf: &[u8]) -> Result<CopyDoneBody, CopyDoneBodyParseError> {
        if !buf.is_empty() {
            return Err(CopyDoneBodyParseError::InvalidLength(buf.len(), 0));
        }
        Ok(CopyDoneBody)
    }
}

#[derive(Debug)]
pub struct UnknownMessageBody {
    pub header: Header,
    pub bytes: Vec<u8>,
}

impl Display for UnknownMessageBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: Unknown")?;
        writeln!(f, "  Tag: '{}'", self.header.tag as char)?;
        writeln!(f, "  Bytes: {:?}", self.bytes)
    }
}

impl UnknownMessageBody {
    fn parse(buf: &[u8], header: Header) -> UnknownMessageBody {
        UnknownMessageBody {
            header,
            bytes: buf.to_vec(),
        }
    }
}

#[derive(Error, Debug)]
enum ReadCStrError {
    #[error("c string is not null terminated")]
    NotNullTerminated,
    #[error("c string is not utf8 formatted")]
    NotUtf8Formatted,
}

impl From<ReadCStrError> for std::io::Error {
    fn from(value: ReadCStrError) -> Self {
        match value {
            ReadCStrError::NotNullTerminated => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "c string is not null terminated".to_string(),
            ),
            ReadCStrError::NotUtf8Formatted => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "c string is utf8 formatted".to_string(),
            ),
        }
    }
}

fn read_cstr(buf: &[u8]) -> Result<(String, usize), ReadCStrError> {
    match buf.iter().position(|b| *b == b'\0') {
        Some(null_pos) => {
            let cstr = unsafe { CStr::from_bytes_with_nul_unchecked(&buf[..(null_pos + 1)]) };
            match cstr.to_str() {
                Ok(str) => Ok((str.to_string(), null_pos + 1)),
                Err(_) => Err(ReadCStrError::NotUtf8Formatted),
            }
        }
        None => Err(ReadCStrError::NotNullTerminated),
    }
}

#[derive(Clone, Copy)]
pub enum ReplicationType {
    Logical,
    Physical,
}

#[derive(Clone, Copy)]
enum ProtocolState {
    Initial,
    NegotiatingSsl,
    StartupDone,
    AuthenticatingSasl(bool),
    RequestedReplication(ReplicationType),
    Replicating(ReplicationType),
}

impl ProtocolState {
    pub fn startup_done(&self) -> bool {
        matches!(self, ProtocolState::StartupDone)
    }

    pub fn expecting_ssl_response(&self) -> bool {
        matches!(self, ProtocolState::NegotiatingSsl)
    }

    pub fn authenticating_sasl(&self) -> bool {
        matches!(self, ProtocolState::AuthenticatingSasl(_))
    }

    pub fn initial_response_sent(&self) -> bool {
        if let ProtocolState::AuthenticatingSasl(sent) = self {
            *sent
        } else {
            panic!("call this method only when authenticating sasl")
        }
    }

    pub fn replication_type(&self) -> Option<ReplicationType> {
        match self {
            ProtocolState::Replicating(ReplicationType::Logical) => Some(ReplicationType::Logical),
            ProtocolState::Replicating(ReplicationType::Physical) => {
                Some(ReplicationType::Physical)
            }
            _ => None,
        }
    }
}

pub fn create_decoders() -> (client::ClientMessageDecoder, server::ServerMessageDecoder) {
    let protocol_state = Arc::new(Mutex::new(ProtocolState::Initial));
    let client_msg_decoder = client::ClientMessageDecoder {
        protocol_state: Arc::clone(&protocol_state),
    };
    let server_msg_decoder = server::ServerMessageDecoder {
        protocol_state,
        row_description: None,
    };
    (client_msg_decoder, server_msg_decoder)
}
