use std::{
    fmt::Display,
    sync::{Arc, Mutex},
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use thiserror::Error;
use tokio_util::codec::Decoder;

use super::ReadCStrError;

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
    fn parse(buf: &mut BytesMut) -> Result<Option<FirstMessage>, ParseFirstMessageError> {
        if buf.len() < 4 {
            // Not enough data to read message length
            return Ok(None);
        }

        // First four bytes contain the length of the message.
        let length = BigEndian::read_i32(&buf[..4]) as usize;

        // Length includes its own four bytes as well so it shouldn't be less than 4
        if length < 4 {
            buf.advance(length);
            return Err(ParseFirstMessageError::LengthTooSmall(length, 4));
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
                None => return Ok(None),
            },
            SSL_REQUEST_TYPE => Ok(Some(FirstMessage::SslRequest)),
            GSS_ENC_REQUEST_TYPE => Ok(Some(FirstMessage::GssEncRequest)),
            _ => match StartupMessageBody::parse(length, typ, buf)? {
                Some(body) => Ok(Some(FirstMessage::StartupMessage(body))),
                None => return Ok(None),
            },
        };

        // Use advance to modify buf such that it no longer contains
        // this message.
        buf.advance(length);
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
        length: usize,
        protocol_version: i32,
        buf: &mut BytesMut,
    ) -> Result<Option<StartupMessageBody>, ParseStartupMessageBodyError> {
        if buf.len() < length {
            return Ok(None);
        }
        let mut param_start = 8;
        let mut parameters = Vec::new();
        loop {
            let (param, end_pos) = match super::read_cstr(&buf[param_start..]) {
                Ok(res) => res,
                Err(e) => {
                    buf.advance(length);
                    return Err(e.into());
                }
            };
            parameters.push(param);
            param_start += end_pos;
            if param_start >= length - 1 {
                if buf[length - 1] != 0 {
                    buf.advance(length);
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
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<CancelRequestBody>, ParseCancelRequestBodyError> {
        if length != 16 {
            buf.advance(length);
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
            Some(header) => match header.tag {
                SASL_MESSAGE_TAG => {
                    if initial_response_sent {
                        match ResponseBody::parse(header.length as usize, &buf[5..]) {
                            Some(body) => {
                                Ok(Some((SaslMessage::Response(body), header.msg_length())))
                            }
                            None => Ok(None),
                        }
                    } else {
                        match InitialResponseBody::parse(header.length as usize, &buf[5..])
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
            },
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
    #[error("invalid message length {0}. It can't be less than {1}")]
    LengthTooShort(usize, usize),

    #[error("invalid mechanism: {0}")]
    InvalidMechanism(#[from] ReadCStrError),
}

impl InitialResponseBody {
    fn parse(
        length: usize,
        mut buf: &[u8],
    ) -> Result<Option<InitialResponseBody>, InitialResponseBodyParseError> {
        if length <= 4 {
            return Err(InitialResponseBodyParseError::LengthTooShort(length, 4));
        }

        let (auth_mechanism, end_pos) = super::read_cstr(buf)?;

        buf = &buf[end_pos..];
        let data_length = BigEndian::read_i32(buf);
        let data = if data_length > -1 {
            buf = &buf[4..];
            buf[..data_length as usize].to_vec()
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
    fn parse(length: usize, buf: &[u8]) -> Option<ResponseBody> {
        let data = buf[..(length - 4)].to_vec();

        Some(ResponseBody { data })
    }
}

#[derive(Debug)]
pub enum SubsequentMessage {
    Query(QueryBody),
    CopyData(super::CopyDataBody),
    Terminate,
    Unknown(super::UnknownMessageBody),
}

impl Display for SubsequentMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubsequentMessage::Query(query) => write!(f, "{query}"),
            SubsequentMessage::CopyData(body) => write!(f, "{body}"),
            SubsequentMessage::Terminate => {
                writeln!(f)?;
                writeln!(f, "  Type: Terminate")
            }
            SubsequentMessage::Unknown(body) => write!(f, "{body}"),
        }
    }
}

#[derive(Error, Debug)]
enum SubsequentMessageParseError {
    #[error("invalid message length {0}. It should be {1}")]
    InvalidTerminateLength(usize, usize),

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
            Some(header) => match header.tag {
                QUERY_MESSAGE_TAG => {
                    match QueryBody::parse(&buf[5..])
                        .map_err(|e| (e.into(), header.msg_length()))?
                    {
                        Some(query_body) => Ok(Some((
                            SubsequentMessage::Query(query_body),
                            header.msg_length(),
                        ))),
                        None => Ok(None),
                    }
                }
                COPY_DATA_MESSAGE_TAG => {
                    let body = super::CopyDataBody::parse(header.length as usize, &buf[5..]);
                    Ok(Some((
                        SubsequentMessage::CopyData(body),
                        header.msg_length(),
                    )))
                }
                TERMINATE_MESSAGE_TAG => {
                    if header.length != 4 {
                        return Err((
                            SubsequentMessageParseError::InvalidTerminateLength(
                                4,
                                header.length as usize,
                            ),
                            header.msg_length(),
                        ));
                    }
                    Ok(Some((SubsequentMessage::Terminate, header.msg_length())))
                }
                _ => {
                    let body = super::UnknownMessageBody::parse(&buf[5..], header);
                    Ok(Some((
                        SubsequentMessage::Unknown(body),
                        header.msg_length(),
                    )))
                }
            },
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
            match SubsequentMessage::parse(buf) {
                Ok(msg) => match msg {
                    Some((msg, skip)) => {
                        buf.advance(skip);
                        Ok(Some(ClientMessage::Subsequent(msg)))
                    }
                    None => Ok(None),
                },
                Err((e, skip)) => {
                    buf.advance(skip);
                    Err(e.into())
                }
            }
        } else if state.authenticating_sasl() {
            match SaslMessage::parse(buf, state.initial_response_sent()) {
                Ok(msg) => match msg {
                    Some((msg, skip)) => {
                        buf.advance(skip);
                        if let SaslMessage::InitialResponse(_) = msg {
                            *state = super::ProtocolState::AuthenticatingSasl(true);
                        }
                        Ok(Some(ClientMessage::Sasl(msg)))
                    }
                    None => Ok(None),
                },
                Err((e, skip)) => {
                    buf.advance(skip);
                    return Err(e.into());
                }
            }
        } else {
            match FirstMessage::parse(buf)? {
                Some(msg) => {
                    if let FirstMessage::SslRequest = msg {
                        *state = super::ProtocolState::NegotiatingSsl;
                    }
                    Ok(Some(ClientMessage::First(msg)))
                }
                None => Ok(None),
            }
        }
    }
}
