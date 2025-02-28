use std::{
    fmt::Display,
    str::{from_utf8, Utf8Error},
    sync::{Arc, Mutex},
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use thiserror::Error;
use tokio_util::codec::Decoder;

use super::{CopyDataBodyParseError, ReadCStrError, ReplicationType, NUM_HEADER_BYTES};

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

        match typ {
            CANCEL_REQUEST_TYPE => match CancelRequestBody::parse(payload_buf) {
                Ok(body) => match body {
                    Some(body) => Ok(Some((FirstMessage::CancelRequest(body), length))),
                    None => Ok(None),
                },
                Err(e) => Err((e.into(), length)),
            },
            SSL_REQUEST_TYPE => Ok(Some((FirstMessage::SslRequest, length))),
            GSS_ENC_REQUEST_TYPE => Ok(Some((FirstMessage::GssEncRequest, length))),
            _ => match StartupMessageBody::parse(typ, payload_buf) {
                Ok(body) => match body {
                    Some(body) => Ok(Some((FirstMessage::StartupMessage(body), length))),
                    None => Ok(None),
                },
                Err(e) => Err((e.into(), length)),
            },
        }
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
    raw_data: Vec<u8>,
    // SCRAM-specific fields
    username: Option<String>,
    nonce: Option<String>,
}

impl InitialResponseBody {
    fn parse(mut buf: &[u8]) -> Result<Option<InitialResponseBody>, InitialResponseBodyParseError> {
        let (auth_mechanism, end_pos) = super::read_cstr(buf)?;
        buf = &buf[end_pos..];

        if buf.len() < 4 {
            return Err(InitialResponseBodyParseError::BufferTooShort(buf.len()));
        }

        let data_length = BigEndian::read_i32(buf);
        let raw_data = if data_length > 0 {
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

        let (username, nonce) = if auth_mechanism == "SCRAM-SHA-256" && !raw_data.is_empty() {
            if let Ok(scram_str) = std::str::from_utf8(&raw_data) {
                let parts: Vec<&str> = scram_str.split(',').collect();
                if parts.len() >= 4 {
                    let mut username = None;
                    let mut nonce = None;
                    for part in parts[2..].iter() {
                        match part.split_once('=') {
                            Some(("n", u)) => username = Some(u.to_string()),
                            Some(("r", n)) => nonce = Some(n.to_string()),
                            _ => {}
                        }
                    }
                    (username, nonce)
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        Ok(Some(InitialResponseBody {
            auth_mechanism,
            raw_data,
            username,
            nonce,
        }))
    }
}

impl Display for InitialResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: SASLInitialResponse")?;
        writeln!(f, "  Auth Mechanism: {}", self.auth_mechanism)?;

        if self.auth_mechanism == "SCRAM-SHA-256" {
            if let Some(username) = &self.username {
                writeln!(f, "  Username: {}", username)?;
            }
            if let Some(nonce) = &self.nonce {
                writeln!(f, "  Client Nonce: {}", nonce)?;
            }
            if self.username.is_none() || self.nonce.is_none() {
                writeln!(f, "  Initial Response: {:?}", self.raw_data)?;
            }
        } else {
            writeln!(f, "  Initial Response: {:?}", self.raw_data)?;
        }
        Ok(())
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

#[derive(Debug)]
pub struct ResponseBody {
    raw_data: Vec<u8>,
    // SCRAM-specific fields
    client_final_nonce: Option<String>,
    client_proof: Option<String>,
}

impl ResponseBody {
    fn parse(buf: &[u8]) -> Option<ResponseBody> {
        let raw_data = buf.to_vec();

        // Try to parse SCRAM response
        // Format: c=biws,r=<client-final-nonce>,p=<client-proof>
        let (client_final_nonce, client_proof) =
            if let Ok(scram_str) = std::str::from_utf8(&raw_data) {
                let parts: Vec<&str> = scram_str.split(',').collect();
                let mut nonce = None;
                let mut proof = None;

                for part in parts.iter() {
                    match part.split_once('=') {
                        Some(("r", n)) => nonce = Some(n.to_string()),
                        Some(("p", p)) => proof = Some(p.to_string()),
                        _ => {}
                    }
                }
                (nonce, proof)
            } else {
                (None, None)
            };

        Some(ResponseBody {
            raw_data,
            client_final_nonce,
            client_proof,
        })
    }
}

impl Display for ResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: SASLResponse")?;

        if let Some(nonce) = &self.client_final_nonce {
            writeln!(f, "  Client Final Nonce: {}", nonce)?;
        }
        if let Some(proof) = &self.client_proof {
            writeln!(f, "  Client Proof: {}", proof)?;
        }
        if self.client_final_nonce.is_none() || self.client_proof.is_none() {
            writeln!(f, "  Response: {:?}", self.raw_data)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum SubsequentMessage {
    Query(QueryBody),
    CopyData(super::CopyDataBody),
    CopyFail(CopyFailBody),
    Sync(SyncBody),
    Terminate(TerminateBody),
    Unknown(super::UnknownMessageBody),
}

impl Display for SubsequentMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubsequentMessage::Query(query) => write!(f, "{query}"),
            SubsequentMessage::CopyData(body) => write!(f, "{body}"),
            SubsequentMessage::CopyFail(body) => write!(f, "{body}"),
            SubsequentMessage::Sync(body) => write!(f, "{body}"),
            SubsequentMessage::Terminate(body) => write!(f, "{body}"),
            SubsequentMessage::Unknown(body) => write!(f, "{body}"),
        }
    }
}

#[derive(Error, Debug)]
enum SubsequentMessageParseError {
    #[error("sync body parse error: {0}")]
    SyncBody(#[from] SyncBodyParseError),

    #[error("terminate body parse error: {0}")]
    TerminateBody(#[from] TerminateBodyParseError),

    #[error("query body parse error: {0}")]
    QueryBody(#[from] QueryBodyParseError),

    #[error("copy data body parse error: {0}")]
    CopyData(#[from] CopyDataBodyParseError),

    #[error("copy fail body parse error: {0}")]
    CopyFail(#[from] CopyFailBodyParseError),
}

impl From<SubsequentMessageParseError> for std::io::Error {
    fn from(value: SubsequentMessageParseError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{value}"))
    }
}

const QUERY_MESSAGE_TAG: u8 = b'Q';
const TERMINATE_MESSAGE_TAG: u8 = b'X';
const COPY_DATA_MESSAGE_TAG: u8 = b'd';
const COPY_FAIL_MESSAGE_TAG: u8 = b'f';
const SYNC_MESSAGE_TAG: u8 = b'S';

impl SubsequentMessage {
    fn parse(
        buf: &mut BytesMut,
        replication_type: Option<ReplicationType>,
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
                        let body = super::CopyDataBody::parse(buf, replication_type)
                            .map_err(|e| (e.into(), header.msg_length()))?;
                        Ok(Some((
                            SubsequentMessage::CopyData(body),
                            header.msg_length(),
                        )))
                    }
                    COPY_FAIL_MESSAGE_TAG => {
                        let body = CopyFailBody::parse(buf)
                            .map_err(|e| (e.into(), header.msg_length()))?;
                        Ok(Some((
                            SubsequentMessage::CopyFail(body),
                            header.msg_length(),
                        )))
                    }
                    SYNC_MESSAGE_TAG => {
                        let body =
                            SyncBody::parse(buf).map_err(|e| (e.into(), header.msg_length()))?;
                        Ok(Some((SubsequentMessage::Sync(body), header.msg_length())))
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

enum QueryType {
    LogicalReplication,
    PhysicalReplication,
    Other,
}

impl QueryBody {
    fn parse(buf: &[u8]) -> Result<Option<QueryBody>, QueryBodyParseError> {
        let (query, end_pos) = super::read_cstr(buf)?;

        if end_pos != buf.len() {
            return Err(QueryBodyParseError::TrailingBytes);
        }

        Ok(Some(QueryBody { query }))
    }

    fn query_type(&self) -> QueryType {
        fn is_whitespace(c: char) -> bool {
            c == ' ' || c == '\t' || c == '\r' || c == '\n'
        }

        fn not_whitespace(c: char) -> bool {
            !is_whitespace(c)
        }

        fn skip_while<F>(query: &str, f: F) -> usize
        where
            F: Fn(char) -> bool,
        {
            for (i, c) in query.char_indices() {
                if !f(c) {
                    return i;
                }
            }

            query.len()
        }

        fn get_token(query: &str) -> (String, &str) {
            let whitespace_end = skip_while(query, is_whitespace);
            let query = &query[whitespace_end..];
            let token_end = skip_while(query, not_whitespace);
            let token = query[..token_end].to_lowercase();
            (token, &query[whitespace_end + token_end..])
        }

        let query = self.query.as_str();
        let (token, query) = get_token(query);

        if token == "start_replication" {
            let (token, query) = get_token(query);
            if token == "slot" {
                let (_slot_name, query) = get_token(query);
                let (token, _query) = get_token(query);
                if token == "logical" {
                    return QueryType::LogicalReplication;
                }
            }
            return QueryType::PhysicalReplication;
        }

        QueryType::Other
    }
}

#[derive(Debug)]
pub struct CopyFailBody {
    error_message: String,
}

impl Display for CopyFailBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: CopyFail")?;
        writeln!(f, "  Error: {}", self.error_message)
    }
}

#[derive(Error, Debug)]
enum CopyFailBodyParseError {
    #[error("invalid error message: {0:?}")]
    InvalidErrorMessage(#[from] Utf8Error),
}

impl CopyFailBody {
    fn parse(buf: &[u8]) -> Result<CopyFailBody, CopyFailBodyParseError> {
        let error_message = from_utf8(buf)?.to_string();
        Ok(CopyFailBody { error_message })
    }
}

#[derive(Debug)]
pub struct SyncBody;

impl Display for SyncBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: Sync")
    }
}

#[derive(Error, Debug)]
enum SyncBodyParseError {
    #[error("invalid message length {0}. It should be {1}")]
    InvalidLength(usize, usize),
}

impl SyncBody {
    fn parse(buf: &[u8]) -> Result<SyncBody, SyncBodyParseError> {
        if !buf.is_empty() {
            return Err(SyncBodyParseError::InvalidLength(buf.len(), 0));
        }
        Ok(SyncBody)
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
            match SubsequentMessage::parse(buf, state.replication_type()) {
                Ok(msg) => match msg {
                    Some((msg, skip)) => {
                        if let SubsequentMessage::Query(query) = &msg {
                            match query.query_type() {
                                QueryType::LogicalReplication => {
                                    *state = super::ProtocolState::RequestedReplication(
                                        super::ReplicationType::Logical,
                                    );
                                }
                                QueryType::PhysicalReplication => {
                                    *state = super::ProtocolState::RequestedReplication(
                                        super::ReplicationType::Physical,
                                    );
                                }
                                QueryType::Other => {}
                            }
                        }
                        (Ok(Some(ClientMessage::Subsequent(msg))), skip)
                    }
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
