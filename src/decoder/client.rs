use std::{
    fmt::Display,
    sync::{Arc, Mutex},
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use thiserror::Error;
use tokio_util::codec::Decoder;

use super::{ReadCStrError, NUM_HEADER_BYTES};

#[derive(Debug)]
pub enum ClientMessage {
    First(FirstMessage),
    Sasl(SaslMessage),
    Subsequent(SubsequentMessage),
}

impl Display for ClientMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientMessage::First(msg) => write!(f, "{msg}"),
            ClientMessage::Sasl(msg) => write!(f, "{msg}"),
            ClientMessage::Subsequent(msg) => write!(f, "{msg}"),
        }
    }
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

impl Display for FirstMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirstMessage::StartupMessage(msg) => write!(f, "{msg}"),
            FirstMessage::CancelRequest(req) => write!(f, "{req}"),
            FirstMessage::SslRequest => {
                writeln!(f)?;
                writeln!(f, "  Type: SSLRequest")
            }
            FirstMessage::GssEncRequest => {
                writeln!(f)?;
                writeln!(f, "  Type: GSSENCRequest")
            }
        }
    }
}

const CANCEL_REQUEST_TYPE: i32 = 80877102;
const SSL_REQUEST_TYPE: i32 = 80877103;
const GSS_ENC_REQUEST_TYPE: i32 = 80877104;

#[derive(Error, Debug)]
enum ParseFirstMessageError {
    #[error("invalid message length {0}. It can't be less than {1}")]
    LengthTooSmall(usize, usize),

    #[error("invalid startup message: {0}")]
    Startup(#[from] ParseStartupMessageBodyError),

    #[error("invalid cancel request message: {0}")]
    Cancel(#[from] ParseCancelRequestBodyError),
}

impl From<ParseFirstMessageError> for std::io::Error {
    fn from(value: ParseFirstMessageError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{value}"))
    }
}

impl FirstMessage {
    fn parse(
        buf: &mut BytesMut,
    ) -> Result<Option<(FirstMessage, usize)>, (ParseFirstMessageError, usize)> {
        if buf.len() < 8 {
            // Not enough data to read message length and request code
            buf.reserve(8 - buf.len());
            return Ok(None);
        }

        // First four bytes contain the length of the message.
        let length = BigEndian::read_i32(&buf[..4]) as usize;

        // All startup messages are at least 8 bytes long
        if length < 8 {
            return Err((ParseFirstMessageError::LengthTooSmall(length, 8), length));
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

        let payload_length = length - 8;
        let mut payload_buf = &buf[8..];
        payload_buf = &payload_buf[..payload_length];

        let typ = BigEndian::read_i32(&buf[4..8]);

        let res = match typ {
            CANCEL_REQUEST_TYPE => match CancelRequestBody::parse(payload_buf) {
                Ok(body) => match body {
                    Some(body) => Ok(Some((FirstMessage::CancelRequest(body), length))),
                    None => return Ok(None),
                },
                Err(e) => Err((e.into(), length)),
            },
            SSL_REQUEST_TYPE => Ok(Some((FirstMessage::SslRequest, length))),
            GSS_ENC_REQUEST_TYPE => Ok(Some((FirstMessage::GssEncRequest, length))),
            _ => match StartupMessageBody::parse(typ, &payload_buf) {
                Ok(body) => match body {
                    Some(body) => Ok(Some((FirstMessage::StartupMessage(body), length))),
                    None => return Ok(None),
                },
                Err(e) => Err((e.into(), length)),
            },
        };

        res
    }
}

#[derive(Debug)]
pub struct StartupMessageBody {
    pub protocol_version: i32,
    pub parameters: Vec<String>, // TODO use pairs of parameters ie. Vec<(String, String)
}

impl StartupMessageBody {
    fn major_minor_protocol_version(&self) -> (i16, i16) {
        let major = (self.protocol_version >> 16) as i16;
        let minor = self.protocol_version as i16;
        (major, minor)
    }
}

impl Display for StartupMessageBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: StartupMessage")?;
        let (major, minor) = self.major_minor_protocol_version();
        writeln!(f, "  Protocol Version: {major}.{minor}")?;
        for param_pair in self.parameters.chunks(2) {
            if param_pair.len() == 2 {
                writeln!(f, "  Parameter: {} = {}", param_pair[0], param_pair[1])?;
            } else if param_pair.len() == 1 {
                writeln!(f, "  Parameter: {}", param_pair[0])?;
            } else {
                unreachable!()
            }
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
enum ParseStartupMessageBodyError {
    #[error("invalid param: {0}")]
    InvalidParam(#[from] ReadCStrError),

    #[error("startup message is not null terminated")]
    NotNullTerminated,
}

impl StartupMessageBody {
    fn parse(
        protocol_version: i32,
        buf: &[u8],
    ) -> Result<Option<StartupMessageBody>, ParseStartupMessageBodyError> {
        let mut param_start = 0;
        let mut parameters = Vec::new();
        loop {
            let (param, end_pos) = super::read_cstr(&buf[param_start..])?;
            parameters.push(param);
            param_start += end_pos;
            if param_start >= buf.len() - 1 {
                if buf[buf.len() - 1] != 0 {
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

impl Display for CancelRequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: CancelRequest")?;
        writeln!(f, "  ProcessId: {}", self.process_id)?;
        writeln!(f, "  SecretKey: {}", self.secret_key)
    }
}

#[derive(Error, Debug)]
enum ParseCancelRequestBodyError {
    #[error("invalid length of cancel request. Expected {0}, actual {1}")]
    InvalidLength(usize, usize),
}

impl CancelRequestBody {
    fn parse(buf: &[u8]) -> Result<Option<CancelRequestBody>, ParseCancelRequestBodyError> {
        if buf.len() != 8 {
            return Err(ParseCancelRequestBodyError::InvalidLength(8, buf.len()));
        }

        Ok(Some(CancelRequestBody {
            process_id: BigEndian::read_i32(&buf[0..4]),
            secret_key: BigEndian::read_i32(&buf[4..8]),
        }))
    }
}

#[derive(Debug)]
pub enum SaslMessage {
    InitialResponse(InitialResponseBody),
    Response(ResponseBody),
}

impl Display for SaslMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaslMessage::InitialResponse(body) => write!(f, "{body}"),
            SaslMessage::Response(body) => write!(f, "{body}"),
        }
    }
}

const SASL_MESSAGE_TAG: u8 = b'p';

impl SaslMessage {
    fn parse(
        buf: &mut BytesMut,
        initial_response_sent: bool,
    ) -> Result<Option<(SaslMessage, usize)>, (SaslMessageParseError, usize)> {
        match super::Header::parse(buf) {
            Some(header) => {
                let mut buf = &buf[NUM_HEADER_BYTES..];
                buf = &buf[..header.payload_length()];
                match header.tag {
                    SASL_MESSAGE_TAG => {
                        if initial_response_sent {
                            match ResponseBody::parse(buf) {
                                Some(body) => {
                                    Ok(Some((SaslMessage::Response(body), header.msg_length())))
                                }
                                None => Ok(None),
                            }
                        } else {
                            match InitialResponseBody::parse(buf)
                                .map_err(|e| (e.into(), header.msg_length()))?
                            {
                                Some(body) => Ok(Some((
                                    SaslMessage::InitialResponse(body),
                                    header.msg_length(),
                                ))),
                                None => Ok(None),
                            }
                        }
                    }
                    _ => {
                        panic!("Invalid message with tag {}", header.tag);
                    }
                }
            }
            None => Ok(None),
        }
    }
}

#[derive(Error, Debug)]
enum SaslMessageParseError {
    #[error("sasl initial response parse error: {0}")]
    InitialResponse(#[from] InitialResponseBodyParseError),
}

impl From<SaslMessageParseError> for std::io::Error {
    fn from(value: SaslMessageParseError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{value}"))
    }
}

#[derive(Debug)]
pub struct InitialResponseBody {
    auth_mechanism: String,
    data: Vec<u8>,
}

impl Display for InitialResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: SASLInitialResponse")?;
        writeln!(f, "  Auth Mechanism: {}", self.auth_mechanism)?;
        writeln!(f, "  Initial Response: {:?}", self.data)
    }
}

#[derive(Error, Debug)]
enum InitialResponseBodyParseError {
    #[error("buffer length too short: {0}")]
    BufferTooShort(usize),

    #[error("invalid response length: {0}")]
    InvalidResponseLength(i32),

    #[error("invalid mechanism: {0}")]
    InvalidMechanism(#[from] ReadCStrError),
}

impl InitialResponseBody {
    fn parse(mut buf: &[u8]) -> Result<Option<InitialResponseBody>, InitialResponseBodyParseError> {
        let (auth_mechanism, end_pos) = super::read_cstr(buf)?;

        buf = &buf[end_pos..];

        if buf.len() < 4 {
            return Err(InitialResponseBodyParseError::BufferTooShort(buf.len()));
        }

        let data_length = BigEndian::read_i32(buf);
        let data = if data_length > 0 {
            buf = &buf[4..];
            if data_length as usize != buf.len() {
                return Err(InitialResponseBodyParseError::InvalidResponseLength(
                    data_length,
                ));
            }
            buf[..data_length as usize].to_vec()
        } else if data_length < -1 {
            return Err(InitialResponseBodyParseError::InvalidResponseLength(
                data_length,
            ));
        } else {
            Vec::new()
        };

        Ok(Some(InitialResponseBody {
            auth_mechanism,
            data,
        }))
    }
}

#[derive(Debug)]
pub struct ResponseBody {
    data: Vec<u8>,
}

impl Display for ResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: SASLResponse")?;
        writeln!(f, "  Auth Mechanism: SASLInitialResponse")?;
        writeln!(f, "  data: {:?}", self.data)
    }
}

impl ResponseBody {
    fn parse(buf: &[u8]) -> Option<ResponseBody> {
        Some(ResponseBody { data: buf.to_vec() })
    }
}

#[derive(Debug)]
pub enum SubsequentMessage {
    Query(QueryBody),
    CopyData(super::CopyDataBody),
    Terminate(TerminateBody),
    Unknown(super::UnknownMessageBody),
}

impl Display for SubsequentMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubsequentMessage::Query(query) => write!(f, "{query}"),
            SubsequentMessage::CopyData(body) => write!(f, "{body}"),
            SubsequentMessage::Terminate(body) => write!(f, "{body}"),
            SubsequentMessage::Unknown(body) => write!(f, "{body}"),
        }
    }
}

#[derive(Error, Debug)]
enum SubsequentMessageParseError {
    #[error("terminate body parse error: {0}")]
    TerminateBody(#[from] TerminateBodyParseError),

    #[error("query body parse error: {0}")]
    QueryBody(#[from] QueryBodyParseError),
}

impl From<SubsequentMessageParseError> for std::io::Error {
    fn from(value: SubsequentMessageParseError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{value}"))
    }
}

const QUERY_MESSAGE_TAG: u8 = b'Q';
const TERMINATE_MESSAGE_TAG: u8 = b'X';
const COPY_DATA_MESSAGE_TAG: u8 = b'd';

impl SubsequentMessage {
    fn parse(
        buf: &mut BytesMut,
    ) -> Result<Option<(SubsequentMessage, usize)>, (SubsequentMessageParseError, usize)> {
        match super::Header::parse(buf) {
            Some(header) => {
                let mut buf = &buf[NUM_HEADER_BYTES..];
                buf = &buf[..header.payload_length()];
                match header.tag {
                    QUERY_MESSAGE_TAG => {
                        match QueryBody::parse(buf).map_err(|e| (e.into(), header.msg_length()))? {
                            Some(query_body) => Ok(Some((
                                SubsequentMessage::Query(query_body),
                                header.msg_length(),
                            ))),
                            None => Ok(None),
                        }
                    }
                    COPY_DATA_MESSAGE_TAG => {
                        let body = super::CopyDataBody::parse(buf);
                        Ok(Some((
                            SubsequentMessage::CopyData(body),
                            header.msg_length(),
                        )))
                    }
                    TERMINATE_MESSAGE_TAG => {
                        let body = TerminateBody::parse(buf)
                            .map_err(|e| (e.into(), header.msg_length()))?;
                        Ok(Some((
                            SubsequentMessage::Terminate(body),
                            header.msg_length(),
                        )))
                    }
                    _ => {
                        let body = super::UnknownMessageBody::parse(buf, header);
                        Ok(Some((
                            SubsequentMessage::Unknown(body),
                            header.msg_length(),
                        )))
                    }
                }
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug)]
pub struct QueryBody {
    pub query: String,
}

impl Display for QueryBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: Query")?;
        writeln!(f, "  Query: {}", self.query)
    }
}

#[derive(Error, Debug)]
enum QueryBodyParseError {
    #[error("invalid query: {0}")]
    InvalidQuery(#[from] ReadCStrError),

    #[error("trailing bytes after query string")]
    TrailingBytes,
}

impl QueryBody {
    fn parse(buf: &[u8]) -> Result<Option<QueryBody>, QueryBodyParseError> {
        let (query, end_pos) = super::read_cstr(buf)?;

        if end_pos != buf.len() {
            return Err(QueryBodyParseError::TrailingBytes);
        }

        Ok(Some(QueryBody { query }))
    }
}

#[derive(Debug)]
pub struct TerminateBody;

impl Display for TerminateBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: Terminate")
    }
}

#[derive(Error, Debug)]
enum TerminateBodyParseError {
    #[error("invalid message length {0}. It should be {1}")]
    InvalidLength(usize, usize),
}

impl TerminateBody {
    fn parse(buf: &[u8]) -> Result<TerminateBody, TerminateBodyParseError> {
        if !buf.is_empty() {
            return Err(TerminateBodyParseError::InvalidLength(buf.len(), 0));
        }
        Ok(TerminateBody)
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
        let (res, skip) = if state.startup_done() {
            match SubsequentMessage::parse(buf) {
                Ok(msg) => match msg {
                    Some((msg, skip)) => (Ok(Some(ClientMessage::Subsequent(msg))), skip),
                    None => (Ok(None), 0),
                },
                Err((e, skip)) => (Err(e.into()), skip),
            }
        } else if state.authenticating_sasl() {
            match SaslMessage::parse(buf, state.initial_response_sent()) {
                Ok(msg) => match msg {
                    Some((msg, skip)) => {
                        if let SaslMessage::InitialResponse(_) = msg {
                            *state = super::ProtocolState::AuthenticatingSasl(true);
                        }
                        (Ok(Some(ClientMessage::Sasl(msg))), skip)
                    }
                    None => (Ok(None), 0),
                },
                Err((e, skip)) => (Err(e.into()), skip),
            }
        } else {
            match FirstMessage::parse(buf) {
                Ok(msg) => match msg {
                    Some((msg, skip)) => {
                        if let FirstMessage::SslRequest = msg {
                            *state = super::ProtocolState::NegotiatingSsl;
                        }
                        (Ok(Some(ClientMessage::First(msg))), skip)
                    }
                    None => (Ok(None), 0),
                },
                Err((e, skip)) => (Err(e.into()), skip),
            }
        };
        buf.advance(skip);
        res
    }
}
