use std::sync::{Arc, Mutex};

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use tokio_util::codec::Decoder;

use super::{HeaderParseError, ReadCStrError};

#[derive(Debug)]
pub enum ServerMessage {
    Authentication(AuthenticationRequest),
    Ssl(SslResponse),
    ParameterStatus(ParameterStatusBody),
    BackendKeyData(BackendKeyDataBody),
    Unknown(super::UnknownMessageBody),
}

enum ServerMessageParseError {
    Header(HeaderParseError),
    Ssl(SslResponseParseError),
    Authentication(AuthenticationRequestParseError),
    ParamStatus(ParameterStatusBodyParseError),
    BackendKeyData(BackendKeyDataBodyParseError),
}

impl From<HeaderParseError> for ServerMessageParseError {
    fn from(value: HeaderParseError) -> Self {
        ServerMessageParseError::Header(value)
    }
}

impl From<SslResponseParseError> for ServerMessageParseError {
    fn from(value: SslResponseParseError) -> Self {
        ServerMessageParseError::Ssl(value)
    }
}

impl From<AuthenticationRequestParseError> for ServerMessageParseError {
    fn from(value: AuthenticationRequestParseError) -> Self {
        ServerMessageParseError::Authentication(value)
    }
}

impl From<ParameterStatusBodyParseError> for ServerMessageParseError {
    fn from(value: ParameterStatusBodyParseError) -> Self {
        ServerMessageParseError::ParamStatus(value)
    }
}

impl From<BackendKeyDataBodyParseError> for ServerMessageParseError {
    fn from(value: BackendKeyDataBodyParseError) -> Self {
        ServerMessageParseError::BackendKeyData(value)
    }
}

impl From<ServerMessageParseError> for std::io::Error {
    fn from(value: ServerMessageParseError) -> Self {
        match value {
            ServerMessageParseError::Header(e) => e.into(),
            ServerMessageParseError::Ssl(e) => e.into(),
            ServerMessageParseError::Authentication(e) => e.into(),
            ServerMessageParseError::ParamStatus(e) => e.into(),
            ServerMessageParseError::BackendKeyData(e) => e.into(),
        }
    }
}

const AUTHENTICATION_MESSAGE_TAG: u8 = b'R';
const PARAM_STATUS_MESSAGE_TAG: u8 = b'S';
const BACKEND_KEY_DATA_MESSAGE_TAG: u8 = b'K';

impl ServerMessage {
    fn parse(
        buf: &mut BytesMut,
        expecting_ssl_response: bool,
    ) -> Result<Option<ServerMessage>, ServerMessageParseError> {
        if expecting_ssl_response {
            match SslResponse::parse(buf)? {
                Some(msg) => Ok(Some(ServerMessage::Ssl(msg))),
                None => Ok(None),
            }
        } else {
            match super::Header::parse(buf)? {
                Some(header) => {
                    let res = match header.tag {
                        AUTHENTICATION_MESSAGE_TAG => {
                            match AuthenticationRequest::parse(header.length as usize, buf)? {
                                Some(auth_req) => Ok(Some(ServerMessage::Authentication(auth_req))),
                                None => Ok(None),
                            }
                        }
                        PARAM_STATUS_MESSAGE_TAG => {
                            match ParameterStatusBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(ServerMessage::ParameterStatus(body))),
                                None => Ok(None),
                            }
                        }
                        BACKEND_KEY_DATA_MESSAGE_TAG => {
                            match BackendKeyDataBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(ServerMessage::BackendKeyData(body))),
                                None => Ok(None),
                            }
                        }
                        _ => match super::UnknownMessageBody::parse(&buf[5..], header) {
                            Some(body) => Ok(Some(ServerMessage::Unknown(body))),
                            None => Ok(None),
                        },
                    };
                    buf.advance(header.length as usize + 1);
                    res
                }
                None => Ok(None),
            }
        }
    }
}

#[derive(Debug)]
pub enum AuthenticationRequest {
    AuthenticationOk,
    AuthenticationKerberosV5,
    AuthenticationCleartextPassword,
    AuthenticationMd5Password,
    AuthenticationGss,
    AuthenticationGssContinue,
    AuthenticationSspi,
    AuthenticationSasl,
    AuthenticationSaslContinue,
    AuthenticationSaslFinal,
}

enum AuthenticationRequestParseError {
    InvalidLength(usize, usize),
    LengthTooShort(usize, usize),
    InvalidType(i32),
}

impl From<AuthenticationRequestParseError> for std::io::Error {
    fn from(value: AuthenticationRequestParseError) -> Self {
        match value {
            AuthenticationRequestParseError::InvalidLength(expected, actual) => {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid length {actual}. It should be {expected}"),
                )
            }
            AuthenticationRequestParseError::LengthTooShort(length, limit) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length {length}. It should be greater than {limit}"),
            ),
            AuthenticationRequestParseError::InvalidType(typ) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid type {typ}"),
            ),
        }
    }
}

const AUTHETICATION_OK_TYPE: i32 = 0;
const AUTHETICATION_KERBEROS_TYPE: i32 = 2;
const AUTHETICATION_CLEARTEXT_PWD_TYPE: i32 = 3;
const AUTHETICATION_MD5_PWD_TYPE: i32 = 5;
const AUTHETICATION_GSS_TYPE: i32 = 7;
const AUTHETICATION_GSS_CONTINUE_TYPE: i32 = 8;
const AUTHETICATION_SSPI_TYPE: i32 = 9;
const AUTHETICATION_SASL_TYPE: i32 = 10;
const AUTHETICATION_SASL_CONTINUE_TYPE: i32 = 11;
const AUTHETICATION_SASL_FINAL_TYPE: i32 = 12;

impl AuthenticationRequest {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<AuthenticationRequest>, AuthenticationRequestParseError> {
        let body_buf = &buf[5..];
        if body_buf.len() < length - 4 {
            return Ok(None);
        }

        let typ = BigEndian::read_i32(body_buf);

        match typ {
            AUTHETICATION_OK_TYPE => {
                if length != 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::InvalidLength(8, length))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationOk))
                }
            }
            AUTHETICATION_KERBEROS_TYPE => {
                if length != 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::InvalidLength(8, length))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationKerberosV5))
                }
            }
            AUTHETICATION_CLEARTEXT_PWD_TYPE => {
                if length != 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::InvalidLength(8, length))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationCleartextPassword))
                }
            }
            AUTHETICATION_MD5_PWD_TYPE => {
                if length != 12 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::InvalidLength(12, length))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationMd5Password))
                }
            }
            AUTHETICATION_GSS_TYPE => {
                if length != 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::InvalidLength(8, length))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationGss))
                }
            }
            AUTHETICATION_GSS_CONTINUE_TYPE => {
                if length <= 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::LengthTooShort(length, 8))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationGssContinue))
                }
            }
            AUTHETICATION_SSPI_TYPE => {
                if length != 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::InvalidLength(8, length))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationSspi))
                }
            }
            AUTHETICATION_SASL_TYPE => {
                if length <= 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::LengthTooShort(length, 8))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationSasl))
                }
            }
            AUTHETICATION_SASL_CONTINUE_TYPE => {
                if length <= 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::LengthTooShort(length, 8))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationSaslContinue))
                }
            }
            AUTHETICATION_SASL_FINAL_TYPE => {
                if length <= 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::LengthTooShort(length, 8))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationSaslFinal))
                }
            }
            typ => {
                buf.advance(length + 1);
                Err(AuthenticationRequestParseError::InvalidType(typ))
            }
        }
    }
}

#[derive(Debug)]
pub struct SslResponse {
    accepted: bool,
}

enum SslResponseParseError {
    InvalidTag(u8),
}

impl From<SslResponseParseError> for std::io::Error {
    fn from(value: SslResponseParseError) -> Self {
        match value {
            SslResponseParseError::InvalidTag(tag) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid SslResponse tag: {tag}"),
            ),
        }
    }
}

impl SslResponse {
    fn parse(buf: &mut BytesMut) -> Result<Option<SslResponse>, SslResponseParseError> {
        if buf.len() < 1 {
            return Ok(None);
        }

        let tag = buf[0];
        let res = match tag {
            b'S' => Ok(Some(SslResponse { accepted: true })),
            b'N' => Ok(Some(SslResponse { accepted: false })),
            tag => Err(SslResponseParseError::InvalidTag(tag)),
        };
        buf.advance(1);
        res
    }
}

#[derive(Debug)]
pub struct ParameterStatusBody {
    pub param_name: String,
    pub param_value: String,
}

enum ParameterStatusBodyParseError {
    InvalidParamName(ReadCStrError),
    InvalidParamValue(ReadCStrError),
}

impl From<ParameterStatusBodyParseError> for std::io::Error {
    fn from(value: ParameterStatusBodyParseError) -> Self {
        match value {
            ParameterStatusBodyParseError::InvalidParamName(e) => e.into(),
            ParameterStatusBodyParseError::InvalidParamValue(e) => e.into(),
        }
    }
}

impl ParameterStatusBody {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<ParameterStatusBody>, ParameterStatusBodyParseError> {
        let body_buf = &buf[5..];
        if body_buf.len() < length - 4 {
            return Ok(None);
        }
        let (param_name, end_pos) = match super::read_cstr(body_buf) {
            Ok(res) => res,
            Err(e) => {
                buf.advance(length + 1);
                return Err(ParameterStatusBodyParseError::InvalidParamName(e));
            }
        };
        let (param_value, _) = match super::read_cstr(&body_buf[end_pos..]) {
            Ok(res) => res,
            Err(e) => {
                buf.advance(length + 1);
                return Err(ParameterStatusBodyParseError::InvalidParamValue(e));
            }
        };

        Ok(Some(ParameterStatusBody {
            param_name,
            param_value,
        }))
    }
}

#[derive(Debug)]
pub struct BackendKeyDataBody {
    pub process_id: i32,
    pub secret_key: i32,
}

enum BackendKeyDataBodyParseError {
    InvalidLength(usize, usize),
}

impl From<BackendKeyDataBodyParseError> for std::io::Error {
    fn from(value: BackendKeyDataBodyParseError) -> Self {
        match value {
            BackendKeyDataBodyParseError::InvalidLength(expected, actual) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length {actual}. It should be {expected}"),
            ),
        }
    }
}

impl BackendKeyDataBody {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<BackendKeyDataBody>, BackendKeyDataBodyParseError> {
        let body_buf = &buf[5..];
        if body_buf.len() < length - 4 {
            return Ok(None);
        }
        let res = if length != 12 {
            buf.advance(length + 1);
            Err(BackendKeyDataBodyParseError::InvalidLength(12, length))
        } else {
            Ok(Some(BackendKeyDataBody {
                process_id: BigEndian::read_i32(&body_buf[..4]),
                secret_key: BigEndian::read_i32(&body_buf[4..8]),
            }))
        };
        res
    }
}

pub struct ServerMessageDecoder {
    pub(super) protocol_state: Arc<Mutex<super::ProtocolState>>,
}

impl Decoder for ServerMessageDecoder {
    type Item = ServerMessage;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut state = self
            .protocol_state
            .lock()
            .expect("failed to lock protocol_state");
        match ServerMessage::parse(buf, state.expecting_ssl_response())? {
            Some(msg) => {
                match msg {
                    ServerMessage::Authentication(AuthenticationRequest::AuthenticationOk) => {
                        *state = super::ProtocolState::AuthenticationOk
                    }
                    ServerMessage::Ssl(SslResponse { accepted }) => {
                        if accepted {
                            *state = super::ProtocolState::SslAccepted
                        } else {
                            *state = super::ProtocolState::SslRejected
                        }
                    }
                    _ => {}
                }
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }
}
