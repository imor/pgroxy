use std::sync::{Arc, Mutex};

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use tokio_util::codec::Decoder;

use super::{HeaderParseError, ReadCStrError, MAX_ALLOWED_MESSAGE_LENGTH};

#[derive(Debug)]
pub enum ClientMessage {
    First(FirstMessage),
    Subsequent(SubsequentMessage),
}

/// FirstMessage is the first message sent by a client to the server.
/// It contains length of the message in the first four bytes interpreted
/// as a big endian i32. The next four bytes contain the type, again
/// interpreted as a big endian i32. The rest of the message varies
/// according to which type it is.
#[derive(Debug)]
pub enum FirstMessage {
    StartupMessage(StartupMessageBody),
    CancelRequest(CancelRequestBody),
    SslRequest,
    GssEncRequest,
}

const CANCEL_REQUEST_TYPE: i32 = 80877102;
const SSL_REQUEST_TYPE: i32 = 80877103;
const GSS_ENC_REQUEST_TYPE: i32 = 80877104;

enum ParseFirstMessageError {
    LengthTooSmall(usize, usize),
    LengthTooLarge(usize, usize),
    Startup(ParseStartupMessageBodyError),
    Cancel(ParseCancelRequestBodyError),
}

impl From<ParseFirstMessageError> for std::io::Error {
    fn from(value: ParseFirstMessageError) -> Self {
        match value {
            ParseFirstMessageError::LengthTooSmall(length, limit) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length {length}. It can't be less than {limit}"),
            ),
            ParseFirstMessageError::LengthTooLarge(length, limit) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Message of length {length} is too large. It can't be greater than {limit}"
                ),
            ),
            ParseFirstMessageError::Startup(e) => e.into(),
            ParseFirstMessageError::Cancel(e) => e.into(),
        }
    }
}

impl From<ParseStartupMessageBodyError> for ParseFirstMessageError {
    fn from(value: ParseStartupMessageBodyError) -> Self {
        ParseFirstMessageError::Startup(value)
    }
}

impl From<ParseCancelRequestBodyError> for ParseFirstMessageError {
    fn from(value: ParseCancelRequestBodyError) -> Self {
        ParseFirstMessageError::Cancel(value)
    }
}

impl FirstMessage {
    fn parse(buf: &mut BytesMut) -> Result<Option<FirstMessage>, ParseFirstMessageError> {
        if buf.len() < 4 {
            // Not enough data to read message length
            return Ok(None);
        }

        // First four bytes contain the length of the message.
        let length = BigEndian::read_i32(&buf[..4]) as usize;

        // Length includes its own four bytes as well so it shouldn't be less than 4
        if length < 4 {
            return Err(ParseFirstMessageError::LengthTooSmall(length, 4));
        }

        // Check that the length is not too large to avoid a denial of
        // service attack where the proxy runs out of memory.
        if length > super::MAX_ALLOWED_MESSAGE_LENGTH {
            return Err(ParseFirstMessageError::LengthTooLarge(
                length,
                MAX_ALLOWED_MESSAGE_LENGTH,
            ));
        }

        if buf.len() < length {
            // The full message has not yet arrived.
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            buf.reserve(length - buf.len());

            // We inform the Framed that we need more bytes to form the next
            // frame.
            return Ok(None);
        }

        let typ = BigEndian::read_i32(&buf[4..8]);
        let res = match typ {
            CANCEL_REQUEST_TYPE => match CancelRequestBody::parse(length, buf)? {
                Some(body) => Ok(Some(FirstMessage::CancelRequest(body))),
                None => Ok(None),
            },
            SSL_REQUEST_TYPE => Ok(Some(FirstMessage::SslRequest)),
            GSS_ENC_REQUEST_TYPE => Ok(Some(FirstMessage::GssEncRequest)),
            _ => match StartupMessageBody::parse(length, typ, buf)? {
                Some(body) => Ok(Some(FirstMessage::StartupMessage(body))),
                None => Ok(None),
            },
        };

        // Use advance to modify buf such that it no longer contains
        // this message.
        // println!("Advancing over {length} bytes");
        buf.advance(length);
        res
    }
}

#[derive(Debug)]
pub struct StartupMessageBody {
    pub protocol_version: i32,
    pub parameters: Vec<String>, // TODO use pairs of parameters ie. Vec<(String, String)
}

enum ParseStartupMessageBodyError {
    InvalidParam(ReadCStrError),
    NotNullTerminated,
}

impl From<ParseStartupMessageBodyError> for std::io::Error {
    fn from(value: ParseStartupMessageBodyError) -> Self {
        match value {
            ParseStartupMessageBodyError::InvalidParam(e) => e.into(),
            ParseStartupMessageBodyError::NotNullTerminated => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid startup message: not null terminated",
            ),
        }
    }
}

impl From<ReadCStrError> for ParseStartupMessageBodyError {
    fn from(value: ReadCStrError) -> Self {
        ParseStartupMessageBodyError::InvalidParam(value)
    }
}

impl StartupMessageBody {
    fn parse(
        length: usize,
        protocol_version: i32,
        buf: &[u8],
    ) -> Result<Option<StartupMessageBody>, ParseStartupMessageBodyError> {
        let mut param_start = 8;
        let mut parameters = Vec::new();
        loop {
            let (param, end_pos) = super::read_cstr(&buf[param_start..])?;
            parameters.push(param);
            param_start += end_pos;
            if param_start >= length - 1 {
                if buf[length - 1] != 0 {
                    return Err(ParseStartupMessageBodyError::NotNullTerminated);
                }
                break;
            }
        }
        Ok(Some(StartupMessageBody {
            protocol_version,
            parameters,
        }))
    }
}

#[derive(Debug)]
pub struct CancelRequestBody {
    pub process_id: i32,
    pub secret_key: i32,
}

enum ParseCancelRequestBodyError {
    InvalidLength(usize, usize),
}

impl From<ParseCancelRequestBodyError> for std::io::Error {
    fn from(value: ParseCancelRequestBodyError) -> Self {
        match value {
            ParseCancelRequestBodyError::InvalidLength(expected, actual) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid Cancel message length. Expected {expected}, actual {actual}"),
            ),
        }
    }
}

impl CancelRequestBody {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<CancelRequestBody>, ParseCancelRequestBodyError> {
        if length != 16 {
            return Err(ParseCancelRequestBodyError::InvalidLength(16, length));
        }
        if buf.len() < 16 {
            buf.reserve(length - buf.len());
            return Ok(None);
        }
        Ok(Some(CancelRequestBody {
            process_id: BigEndian::read_i32(&buf[8..12]),
            secret_key: BigEndian::read_i32(&buf[12..16]),
        }))
    }
}

#[derive(Debug)]
pub enum SubsequentMessage {
    Query(QueryBody),
    Unknown(super::UnknownMessageBody),
    Terminate,
}

enum ParseSubsequenceMessageError {
    InvalidTerminateLength(usize, usize),
    Header(HeaderParseError),
    QueryBody(QueryBodyParseError),
}

impl From<ParseSubsequenceMessageError> for std::io::Error {
    fn from(value: ParseSubsequenceMessageError) -> Self {
        match value {
            ParseSubsequenceMessageError::InvalidTerminateLength(expected, actual) => {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Invalid Terminate message length. Expected {expected}, actual {actual}"
                    ),
                )
            }
            ParseSubsequenceMessageError::Header(e) => e.into(),
            ParseSubsequenceMessageError::QueryBody(e) => e.into(),
        }
    }
}

impl From<HeaderParseError> for ParseSubsequenceMessageError {
    fn from(value: HeaderParseError) -> Self {
        ParseSubsequenceMessageError::Header(value)
    }
}

impl From<QueryBodyParseError> for ParseSubsequenceMessageError {
    fn from(value: QueryBodyParseError) -> Self {
        ParseSubsequenceMessageError::QueryBody(value)
    }
}

const QUERY_MESSAGE_TAG: u8 = b'Q';
const TERMINATE_MESSAGE_TAG: u8 = b'X';

impl SubsequentMessage {
    fn parse(
        buf: &mut BytesMut,
    ) -> Result<Option<SubsequentMessage>, ParseSubsequenceMessageError> {
        match super::Header::parse(buf)? {
            Some(header) => {
                let res = match header.tag {
                    QUERY_MESSAGE_TAG => {
                        match QueryBody::parse(header.length as usize, &buf[5..])? {
                            Some(query_body) => Ok(Some(SubsequentMessage::Query(query_body))),
                            None => Ok(None),
                        }
                    }
                    TERMINATE_MESSAGE_TAG => {
                        if header.length != 4 {
                            return Err(ParseSubsequenceMessageError::InvalidTerminateLength(
                                4,
                                header.length as usize,
                            ));
                        }
                        Ok(Some(SubsequentMessage::Terminate))
                    }
                    _ => match super::UnknownMessageBody::parse(&buf[5..], header) {
                        Some(body) => Ok(Some(SubsequentMessage::Unknown(body))),
                        None => Ok(None),
                    },
                };
                // println!("Advancing over {} bytes", header.length + 1);
                buf.advance(header.length as usize + 1);
                res
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug)]
pub struct QueryBody {
    pub query: String,
}

enum QueryBodyParseError {
    LengthTooShort(usize, usize),
    InvalidQuery(ReadCStrError),
}

impl From<QueryBodyParseError> for std::io::Error {
    fn from(value: QueryBodyParseError) -> Self {
        match value {
            QueryBodyParseError::LengthTooShort(length, limit) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length {length} for Query message. It should be at least {limit}"),
            ),
            QueryBodyParseError::InvalidQuery(e) => e.into(),
        }
    }
}

impl From<ReadCStrError> for QueryBodyParseError {
    fn from(value: ReadCStrError) -> Self {
        QueryBodyParseError::InvalidQuery(value)
    }
}

impl QueryBody {
    fn parse(length: usize, buf: &[u8]) -> Result<Option<QueryBody>, QueryBodyParseError> {
        if length <= 4 {
            return Err(QueryBodyParseError::LengthTooShort(length, 4));
        }

        let (query, _) = super::read_cstr(buf)?;
        Ok(Some(QueryBody { query }))
    }
}

pub struct ClientMessageDecoder {
    pub(super) protocol_state: Arc<Mutex<super::ProtocolState>>,
}

impl Decoder for ClientMessageDecoder {
    type Item = ClientMessage;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut state = self
            .protocol_state
            .lock()
            .expect("failed to lock protocol_state");
        if state.startup_done() {
            match SubsequentMessage::parse(buf)? {
                Some(msg) => Ok(Some(ClientMessage::Subsequent(msg))),
                None => Ok(None),
            }
        } else {
            match FirstMessage::parse(buf)? {
                Some(msg) => {
                    match msg {
                        FirstMessage::SslRequest => {
                            *state = super::ProtocolState::SslRequestSent;
                        }
                        _ => {}
                    }
                    Ok(Some(ClientMessage::First(msg)))
                }
                None => Ok(None),
            }
        }
    }
}
