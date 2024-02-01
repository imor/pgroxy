use std::{
    fmt::Display,
    sync::{Arc, Mutex},
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use thiserror::Error;
use tokio_util::codec::Decoder;

use super::{
    read_cstr, CopyDataBody, CopyDataBodyParseError, CopyDoneBody, CopyDoneBodyParseError,
    HeaderParseError, ReadCStrError,
};

#[derive(Debug)]
pub enum ServerMessage {
    Authentication(AuthenticationRequest),
    Ssl(SslResponse),
    ParameterStatus(ParameterStatusBody),
    BackendKeyData(BackendKeyDataBody),
    ReadyForQuery(ReadyForQueryBody),
    RowDescription(RowDescriptionBody),
    CommandCompelte(CommandCompleteBody),
    DataRow(DataRowBody),
    CopyData(CopyDataBody),
    CopyIn(CopyInResponseBody),
    CopyOut(CopyOutResponseBody),
    CopyBoth(CopyBothResponseBody),
    CopyDone(CopyDoneBody),
    Error(ErrorResponseBody),
    Unknown(super::UnknownMessageBody),
}

impl Display for ServerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerMessage::Authentication(body) => write!(f, "{body}"),
            ServerMessage::Ssl(body) => write!(f, "{body}"),
            ServerMessage::ParameterStatus(body) => write!(f, "{body}"),
            ServerMessage::BackendKeyData(body) => write!(f, "{body}"),
            ServerMessage::ReadyForQuery(body) => write!(f, "{body}"),
            ServerMessage::RowDescription(body) => write!(f, "{body}"),
            ServerMessage::CommandCompelte(body) => write!(f, "{body}"),
            ServerMessage::DataRow(body) => write!(f, "{body}"),
            ServerMessage::CopyData(body) => write!(f, "{body}"),
            ServerMessage::CopyIn(body) => write!(f, "{body}"),
            ServerMessage::CopyOut(body) => write!(f, "{body}"),
            ServerMessage::CopyBoth(body) => write!(f, "{body}"),
            ServerMessage::CopyDone(body) => write!(f, "{body}"),
            ServerMessage::Error(body) => write!(f, "{body}"),
            ServerMessage::Unknown(body) => write!(f, "{body}"),
        }
    }
}

#[derive(Error, Debug)]
enum ServerMessageParseError {
    #[error("invalid header: {0}")]
    Header(#[from] HeaderParseError),

    #[error("invalid ssl response: {0}")]
    Ssl(#[from] SslResponseParseError),

    #[error("invalid authentication request message: {0}")]
    Authentication(#[from] AuthenticationRequestParseError),

    #[error("invalid parameter status message: {0}")]
    ParamStatus(#[from] ParameterStatusBodyParseError),

    #[error("invalid backend key data message: {0}")]
    BackendKeyData(#[from] BackendKeyDataBodyParseError),

    #[error("invalid row description body message: {0}")]
    RowDescription(#[from] RowDescriptionBodyParseError),

    #[error("invalid command complete message: {0}")]
    CommandComplete(#[from] CommandCompleteBodyParseError),

    #[error("invalid data row body message: {0}")]
    DataRow(#[from] DataRowBodyParseError),

    #[error("invalid copy data message: {0}")]
    CopyData(#[from] CopyDataBodyParseError),

    #[error("invalid copy in message: {0}")]
    CopyIn(#[from] CopyInResponseBodyParseError),

    #[error("invalid copy out message: {0}")]
    CopyOut(#[from] CopyOutResponseBodyParseError),

    #[error("invalid copy both message: {0}")]
    CopyBoth(#[from] CopyBothResponseBodyParseError),

    #[error("invalid copy done message: {0}")]
    CopyDone(#[from] CopyDoneBodyParseError),

    #[error("invalid error response message: {0}")]
    Error(#[from] ErrorResponseBodyParseError),

    #[error("invalid ready for query message: {0}")]
    ReadyForQuery(#[from] ReadyForQueryBodyParseError),
}

impl From<ServerMessageParseError> for std::io::Error {
    fn from(value: ServerMessageParseError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{value}"))
    }
}

const AUTHENTICATION_MESSAGE_TAG: u8 = b'R';
const PARAM_STATUS_MESSAGE_TAG: u8 = b'S';
const BACKEND_KEY_DATA_MESSAGE_TAG: u8 = b'K';
const READY_FOR_QUERY_MESSAGE_TAG: u8 = b'Z';
const ROW_DESCRIPTION_MESSAGE_TAG: u8 = b'T';
const COMMAND_COMPLETE_MESSAGE_TAG: u8 = b'C';
const DATA_ROW_MESSAGE_TAG: u8 = b'D';
const COPY_IN_MESSAGE_TAG: u8 = b'G';
const COPY_OUT_MESSAGE_TAG: u8 = b'H'; //todo: parse only in copy mode as flush message also has this tag
const COPY_DATA_MESSAGE_TAG: u8 = b'd';
const COPY_BOTH_MESSAGE_TAG: u8 = b'W';
const COPY_DONE_MESSAGE_TAG: u8 = b'c';
const ERROR_RESPONSE_MESSAGE_TAG: u8 = b'E';

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
                                None => return Ok(None),
                            }
                        }
                        PARAM_STATUS_MESSAGE_TAG => {
                            match ParameterStatusBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(ServerMessage::ParameterStatus(body))),
                                None => return Ok(None),
                            }
                        }
                        BACKEND_KEY_DATA_MESSAGE_TAG => {
                            match BackendKeyDataBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(ServerMessage::BackendKeyData(body))),
                                None => return Ok(None),
                            }
                        }
                        READY_FOR_QUERY_MESSAGE_TAG => {
                            match ReadyForQueryBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::ReadyForQuery(body))),
                                None => return Ok(None),
                            }
                        }
                        ROW_DESCRIPTION_MESSAGE_TAG => {
                            match RowDescriptionBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::RowDescription(body))),
                                None => return Ok(None),
                            }
                        }
                        COMMAND_COMPLETE_MESSAGE_TAG => {
                            match CommandCompleteBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::CommandCompelte(body))),
                                None => return Ok(None),
                            }
                        }
                        DATA_ROW_MESSAGE_TAG => {
                            match DataRowBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::DataRow(body))),
                                None => return Ok(None),
                            }
                        }
                        COPY_DATA_MESSAGE_TAG => {
                            match CopyDataBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::CopyData(body))),
                                None => return Ok(None),
                            }
                        }
                        COPY_IN_MESSAGE_TAG => {
                            match CopyInResponseBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::CopyIn(body))),
                                None => return Ok(None),
                            }
                        }
                        COPY_OUT_MESSAGE_TAG => {
                            match CopyOutResponseBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::CopyOut(body))),
                                None => return Ok(None),
                            }
                        }
                        COPY_BOTH_MESSAGE_TAG => {
                            match CopyBothResponseBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::CopyBoth(body))),
                                None => return Ok(None),
                            }
                        }
                        COPY_DONE_MESSAGE_TAG => {
                            match CopyDoneBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::CopyDone(body))),
                                None => return Ok(None),
                            }
                        }
                        ERROR_RESPONSE_MESSAGE_TAG => {
                            match ErrorResponseBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::Error(body))),
                                None => return Ok(None),
                            }
                        }
                        _ => match super::UnknownMessageBody::parse(&buf[5..], header) {
                            Some(body) => Ok(Some(ServerMessage::Unknown(body))),
                            None => return Ok(None),
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

//TODO: Some variants have byte data, add that.
#[derive(Debug)]
pub enum AuthenticationRequest {
    AuthenticationOk,
    AuthenticationKerberosV5,
    AuthenticationCleartextPassword,
    AuthenticationMd5Password,
    AuthenticationGss,
    AuthenticationGssContinue,
    AuthenticationSspi,
    AuthenticationSasl(SaslBody),
    AuthenticationSaslContinue,
    AuthenticationSaslFinal,
}

impl Display for AuthenticationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        if let AuthenticationRequest::AuthenticationSasl(body) = self {
            writeln!(f, "{body}")?;
            return Ok(());
        }
        let typ = match self {
            AuthenticationRequest::AuthenticationOk => "AuthenticationOk",
            AuthenticationRequest::AuthenticationKerberosV5 => "AuthenticationKerberosV5",
            AuthenticationRequest::AuthenticationCleartextPassword => {
                "AuthenticationCleartextPassword"
            }
            AuthenticationRequest::AuthenticationMd5Password => "AuthenticationMD5Password",
            AuthenticationRequest::AuthenticationGss => "AuthenticationGSS",
            AuthenticationRequest::AuthenticationGssContinue => "AuthenticationGSSContinue",
            AuthenticationRequest::AuthenticationSspi => "AuthenticationSSPI",
            AuthenticationRequest::AuthenticationSasl(_) => "AuthenticationSASL",
            AuthenticationRequest::AuthenticationSaslContinue => "AuthenticationSASLContinue",
            AuthenticationRequest::AuthenticationSaslFinal => "AuthenticationSASLFinal",
        };
        writeln!(f, "  Type: {typ}")
    }
}

#[derive(Error, Debug)]
enum AuthenticationRequestParseError {
    #[error("invalid message length {0}. It should be {1}")]
    InvalidLength(usize, usize),

    #[error("invalid message length {0}. It can't be greater than {1}")]
    LengthTooShort(usize, usize),

    #[error("invalid type {0}")]
    InvalidType(i32),

    #[error("sasl body parse error: {0}")]
    Sasl(#[from] SaslBodyParseError),
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
                    Err(AuthenticationRequestParseError::InvalidLength(length, 8))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationOk))
                }
            }
            AUTHETICATION_KERBEROS_TYPE => {
                if length != 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::InvalidLength(length, 8))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationKerberosV5))
                }
            }
            AUTHETICATION_CLEARTEXT_PWD_TYPE => {
                if length != 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::InvalidLength(length, 8))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationCleartextPassword))
                }
            }
            AUTHETICATION_MD5_PWD_TYPE => {
                if length != 12 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::InvalidLength(length, 12))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationMd5Password))
                }
            }
            AUTHETICATION_GSS_TYPE => {
                if length != 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::InvalidLength(length, 8))
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
                    Err(AuthenticationRequestParseError::InvalidLength(length, 8))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationSspi))
                }
            }
            AUTHETICATION_SASL_TYPE => {
                if length <= 8 {
                    buf.advance(length + 1);
                    Err(AuthenticationRequestParseError::LengthTooShort(length, 8))
                } else {
                    match SaslBody::parse(length, buf)? {
                        Some(body) => Ok(Some(AuthenticationRequest::AuthenticationSasl(body))),
                        None => Ok(None),
                    }
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
pub struct SaslBody {
    auth_mechanisms: Vec<String>,
}

impl Display for SaslBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: AuthenticationSASL")?;
        for mechanism in &self.auth_mechanisms {
            writeln!(f, "  Auth Mechanism: {mechanism}")?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
enum SaslBodyParseError {
    #[error("invalid mechanism: {0}")]
    InvalidMechanism(#[from] ReadCStrError),

    #[error("sasl message is not null terminated")]
    NotNullTerminated,
}

impl SaslBody {
    fn parse(length: usize, buf: &mut BytesMut) -> Result<Option<SaslBody>, SaslBodyParseError> {
        let mut mechanism_start = 9;
        let mut auth_mechanisms = Vec::new();
        loop {
            let (mechanism, end_pos) = match super::read_cstr(&buf[mechanism_start..]) {
                Ok(res) => res,
                Err(e) => {
                    buf.advance(length);
                    return Err(e.into());
                }
            };
            auth_mechanisms.push(mechanism);
            mechanism_start += end_pos;
            if mechanism_start >= length - 1 {
                if buf[length - 1] != 0 {
                    buf.advance(length);
                    return Err(SaslBodyParseError::NotNullTerminated);
                }
                break;
            }
        }
        Ok(Some(SaslBody { auth_mechanisms }))
    }
}

#[derive(Debug)]
pub struct SslResponse {
    accepted: bool,
}

impl Display for SslResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: SSLResponse")?;
        writeln!(f, "  Accepted: {}", self.accepted)
    }
}

#[derive(Error, Debug)]
enum SslResponseParseError {
    #[error("invalid ssl response tag: {0}")]
    InvalidTag(u8),
}

impl SslResponse {
    fn parse(buf: &mut BytesMut) -> Result<Option<SslResponse>, SslResponseParseError> {
        if buf.is_empty() {
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

impl Display for ParameterStatusBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: ParameterStatus")?;
        writeln!(f, "  Parameter: {} = {}", self.param_name, self.param_value)
    }
}

#[derive(Error, Debug)]
enum ParameterStatusBodyParseError {
    #[error("invalid parameter name: {0}")]
    InvalidParamName(ReadCStrError),
    #[error("invalid parameter value: {0}")]
    InvalidParamValue(ReadCStrError),
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

impl Display for BackendKeyDataBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: BackendKeyData")?;
        writeln!(f, "  ProcessId: {}", self.process_id)?;
        writeln!(f, "  SecretKey: {}", self.secret_key)
    }
}

#[derive(Error, Debug)]
enum BackendKeyDataBodyParseError {
    #[error("invalid message length {0}. It should be {1}")]
    InvalidLength(usize, usize),
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

        if length != 12 {
            buf.advance(length + 1);
            Err(BackendKeyDataBodyParseError::InvalidLength(length, 12))
        } else {
            Ok(Some(BackendKeyDataBody {
                process_id: BigEndian::read_i32(&body_buf[..4]),
                secret_key: BigEndian::read_i32(&body_buf[4..8]),
            }))
        }
    }
}

#[derive(Debug)]
pub struct ReadyForQueryBody {
    pub transaction_status: u8,
}

impl ReadyForQueryBody {
    fn trasaction_status(&self) -> &'static str {
        match self.transaction_status {
            b'I' => "Idle",
            b'T' => "In transaction block",
            b'E' => "In failed transaction block",
            _ => "Unknown",
        }
    }
}

impl Display for ReadyForQueryBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: ReadyForQuery")?;
        writeln!(f, "  TransactionStatus: {}", self.trasaction_status())
    }
}

#[derive(Error, Debug)]
enum ReadyForQueryBodyParseError {
    #[error("invalid message length {0}. It should be {1}")]
    InvalidLength(usize, usize),
}

impl ReadyForQueryBody {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<ReadyForQueryBody>, ReadyForQueryBodyParseError> {
        let body_buf = &buf[5..];
        if body_buf.len() < length - 4 {
            return Ok(None);
        }

        if length != 5 {
            buf.advance(length + 1);
            Err(ReadyForQueryBodyParseError::InvalidLength(length, 5))
        } else {
            Ok(Some(ReadyForQueryBody {
                transaction_status: body_buf[0],
            }))
        }
    }
}

#[derive(Debug)]
pub struct RowDescriptionField {
    pub name: String,
    pub oid: i32,
    pub attnum: i16,
    pub typoid: i32,
    pub typlen: i16,
    pub typmod: i32,
    pub format: i16,
}

#[derive(Error, Debug)]
enum RowDescriptionFieldParseError {
    #[error("invalid name {0}")]
    InvalidName(#[from] ReadCStrError),
}

impl RowDescriptionField {
    fn parse(
        buf: &[u8],
    ) -> Result<Option<(RowDescriptionField, usize)>, RowDescriptionFieldParseError> {
        let (name, end_pos) = read_cstr(buf)?;
        let buf = &buf[end_pos..];
        if buf.len() < 18 {
            return Ok(None);
        }

        let oid = BigEndian::read_i32(buf);
        let attnum = BigEndian::read_i16(&buf[4..]);
        let typoid = BigEndian::read_i32(&buf[6..]);
        let typlen = BigEndian::read_i16(&buf[10..]);
        let typmod = BigEndian::read_i32(&buf[12..]);
        let format = BigEndian::read_i16(&buf[16..]);

        Ok(Some((
            RowDescriptionField {
                name,
                oid,
                attnum,
                typoid,
                typlen,
                typmod,
                format,
            },
            end_pos + 18,
        )))
    }
}

#[derive(Debug)]
pub struct RowDescriptionBody {
    pub fields: Vec<RowDescriptionField>,
}

impl Display for RowDescriptionBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: RowDescription")?;
        for field in &self.fields {
            writeln!(
                f,
                "  Field: name = {}, oid = {}, attnum = {}, typeoid = {}, typelen = {}, typmod = {}, format = {}",
                field.name, field.oid, field.attnum, field.typoid, field.typlen, field.typmod, field.format
            )?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
enum RowDescriptionBodyParseError {
    #[error("invalid message length {0}. It can't be less than {1}")]
    LengthTooShort(usize, usize),
    #[error("invalid number of fields {0}")]
    InvalidNumFields(i16),
    #[error("invalid field {0}")]
    InvalidField(#[from] RowDescriptionFieldParseError),
}

impl RowDescriptionBody {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<RowDescriptionBody>, RowDescriptionBodyParseError> {
        let mut body_buf = &buf[5..];
        if length < 6 {
            buf.advance(length + 1);
            return Err(RowDescriptionBodyParseError::LengthTooShort(length, 6));
        }
        if body_buf.len() < length - 4 {
            return Ok(None);
        }
        let num_fields = BigEndian::read_i16(body_buf);
        if num_fields < 0 {
            buf.advance(length + 1);
            return Err(RowDescriptionBodyParseError::InvalidNumFields(num_fields));
        }
        body_buf = &body_buf[2..];
        let mut fields = Vec::with_capacity(num_fields as usize);
        for _ in 0..num_fields {
            let (field, end_pos) = match RowDescriptionField::parse(body_buf) {
                Ok(field) => match field {
                    Some(res) => res,
                    None => return Ok(None),
                },
                Err(e) => {
                    buf.advance(length + 1);
                    return Err(e.into());
                }
            };
            fields.push(field);
            body_buf = &body_buf[end_pos..];
        }
        Ok(Some(RowDescriptionBody { fields }))
    }
}

#[derive(Debug)]
pub struct CommandCompleteBody {
    pub command_tag: String,
}

impl Display for CommandCompleteBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: CommandComplete")?;
        writeln!(f, "  Tag: {}", self.command_tag)
    }
}

#[derive(Error, Debug)]
enum CommandCompleteBodyParseError {
    #[error("invalid message length {0}. It can't be less than {1}")]
    LengthTooShort(usize, usize),

    #[error("invalid command tag: {0}")]
    InvalidCommandTag(#[from] ReadCStrError),
}

impl CommandCompleteBody {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<CommandCompleteBody>, CommandCompleteBodyParseError> {
        let body_buf = &buf[5..];
        if length < 5 {
            buf.advance(length + 1);
            return Err(CommandCompleteBodyParseError::LengthTooShort(length, 5));
        }
        if body_buf.len() < length - 4 {
            return Ok(None);
        }
        let (command_tag, _) = read_cstr(body_buf)?;
        Ok(Some(CommandCompleteBody { command_tag }))
    }
}

#[derive(Debug)]
pub struct DataRowColumn {
    pub value: Vec<u8>,
}

#[derive(Error, Debug)]
enum DataRowColumnParseError {
    #[error("invalid length {0}")]
    InvalidLength(i32),
}

impl DataRowColumn {
    fn parse(buf: &[u8]) -> Result<Option<(DataRowColumn, usize)>, DataRowColumnParseError> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = BigEndian::read_i32(buf);
        // len is -1 when column is null
        if len == -1 {
            return Ok(Some((DataRowColumn { value: Vec::new() }, 4)));
        }
        if len < 0 {
            return Err(DataRowColumnParseError::InvalidLength(len));
        }
        if buf.len() < len as usize + 4 {
            return Ok(None);
        }
        let buf = &buf[4..];
        let value = buf[..len as usize].to_vec();
        let len = len as usize + 4;
        Ok(Some((DataRowColumn { value }, len)))
    }
}

#[derive(Debug)]
pub struct DataRowBody {
    pub columns: Vec<DataRowColumn>,
}

impl Display for DataRowBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: DataRow")?;
        for column in &self.columns {
            writeln!(f, "  Column: value = {:?}", column.value)?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
enum DataRowBodyParseError {
    #[error("invalid message length {0}. It can't be less than {1}")]
    LengthTooShort(usize, usize),

    #[error("invalid number of columns {0}")]
    InvalidNumCols(i16),

    #[error("invalid column length: {0}")]
    InvalidColumnLength(#[from] DataRowColumnParseError),
}

impl DataRowBody {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<DataRowBody>, DataRowBodyParseError> {
        let mut body_buf = &buf[5..];
        if length < 6 {
            buf.advance(length + 1);
            return Err(DataRowBodyParseError::LengthTooShort(length, 6));
        }
        if body_buf.len() < length - 4 {
            return Ok(None);
        }
        let num_cols = BigEndian::read_i16(body_buf);
        if num_cols < 0 {
            buf.advance(length + 1);
            return Err(DataRowBodyParseError::InvalidNumCols(num_cols));
        }
        body_buf = &body_buf[2..];
        let mut columns = Vec::with_capacity(num_cols as usize);
        for _ in 0..num_cols {
            let (column, end_pos) = match DataRowColumn::parse(body_buf) {
                Ok(drc) => match drc {
                    Some(res) => res,
                    None => return Ok(None),
                },
                Err(e) => {
                    buf.advance(length + 1);
                    return Err(e.into());
                }
            };
            columns.push(column);
            body_buf = &body_buf[end_pos..];
        }
        Ok(Some(DataRowBody { columns }))
    }
}

fn format_str(format: i16) -> &'static str {
    match format {
        0 => "text",
        1 => "binary",
        _ => "unknown",
    }
}

#[derive(Debug)]
pub struct CopyInResponseBody {
    format: i8,
    col_formats: Vec<i16>,
}

impl Display for CopyInResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: CopyInResponse")?;
        writeln!(f, "  Format: {}", format_str(self.format as i16))?;
        for col_format in &self.col_formats {
            writeln!(f, "  Column Format: {}", format_str(*col_format))?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
enum CopyInResponseBodyParseError {
    #[error("invalid message length {0}. It can't be less than {1}")]
    LengthTooShort(usize, usize),

    #[error("invalid number of columns {0}")]
    InvalidNumCols(i16),
}

impl CopyInResponseBody {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<CopyInResponseBody>, CopyInResponseBodyParseError> {
        let mut body_buf = &buf[5..];
        if length < 7 {
            buf.advance(length + 1);
            return Err(CopyInResponseBodyParseError::LengthTooShort(length, 7));
        }
        if body_buf.len() < length - 4 {
            return Ok(None);
        }

        let format = body_buf[0] as i8;
        body_buf = &body_buf[1..];
        let num_cols = BigEndian::read_i16(body_buf);

        if num_cols < 0 {
            return Err(CopyInResponseBodyParseError::InvalidNumCols(num_cols));
        }

        let mut col_formats = Vec::new();

        for _ in 0..num_cols {
            let format = BigEndian::read_i16(body_buf);
            col_formats.push(format);
            body_buf = &body_buf[2..];
        }

        Ok(Some(CopyInResponseBody {
            format,
            col_formats,
        }))
    }
}

#[derive(Debug)]
pub struct CopyOutResponseBody {
    format: i8,
    col_formats: Vec<i16>,
}

impl Display for CopyOutResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: CopyOutResponse")?;
        writeln!(f, "  Format: {}", format_str(self.format as i16))?;
        for col_format in &self.col_formats {
            writeln!(f, "  Column Format: {}", format_str(*col_format))?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
enum CopyOutResponseBodyParseError {
    #[error("invalid message length {0}. It can't be less than {1}")]
    LengthTooShort(usize, usize),

    #[error("invalid number of columns {0}")]
    InvalidNumCols(i16),
}

impl CopyOutResponseBody {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<CopyOutResponseBody>, CopyOutResponseBodyParseError> {
        let mut body_buf = &buf[5..];
        if length < 7 {
            buf.advance(length + 1);
            return Err(CopyOutResponseBodyParseError::LengthTooShort(length, 7));
        }
        if body_buf.len() < length - 4 {
            return Ok(None);
        }

        let format = body_buf[0] as i8;
        body_buf = &body_buf[1..];
        let num_cols = BigEndian::read_i16(body_buf);

        if num_cols < 0 {
            return Err(CopyOutResponseBodyParseError::InvalidNumCols(num_cols));
        }

        let mut col_formats = Vec::new();

        for _ in 0..num_cols {
            let format = BigEndian::read_i16(body_buf);
            col_formats.push(format);
            body_buf = &body_buf[2..];
        }

        Ok(Some(CopyOutResponseBody {
            format,
            col_formats,
        }))
    }
}

#[derive(Debug)]
pub struct CopyBothResponseBody {
    format: i8,
    col_formats: Vec<i16>,
}

impl Display for CopyBothResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: CopyBothResponse")?;
        writeln!(f, "  Format: {}", format_str(self.format as i16))?;
        for col_format in &self.col_formats {
            writeln!(f, "  Column Format: {}", format_str(*col_format))?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
enum CopyBothResponseBodyParseError {
    #[error("invalid message length {0}. It can't be less than {1}")]
    LengthTooShort(usize, usize),

    #[error("invalid number of columns {0}")]
    InvalidNumCols(i16),
}

impl CopyBothResponseBody {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<CopyBothResponseBody>, CopyBothResponseBodyParseError> {
        let mut body_buf = &buf[5..];
        if length < 7 {
            buf.advance(length + 1);
            return Err(CopyBothResponseBodyParseError::LengthTooShort(length, 7));
        }
        if body_buf.len() < length - 4 {
            return Ok(None);
        }

        let format = body_buf[0] as i8;
        body_buf = &body_buf[1..];
        let num_cols = BigEndian::read_i16(body_buf);

        if num_cols < 0 {
            return Err(CopyBothResponseBodyParseError::InvalidNumCols(num_cols));
        }

        let mut col_formats = Vec::new();

        for _ in 0..num_cols {
            let format = BigEndian::read_i16(body_buf);
            col_formats.push(format);
            body_buf = &body_buf[2..];
        }

        Ok(Some(CopyBothResponseBody {
            format,
            col_formats,
        }))
    }
}

#[derive(Debug)]
pub struct ErrorField {
    pub code: u8,
    pub value: String,
}

impl ErrorField {
    fn parse(buf: &[u8]) -> Result<Option<(ErrorField, usize)>, ReadCStrError> {
        if buf.len() < 2 {
            return Ok(None);
        }

        let code = buf[0];
        if code == 0 {
            return Ok(Some((
                ErrorField {
                    code: 0,
                    value: "".to_string(),
                },
                1,
            )));
        }
        let (value, end_pos) = read_cstr(&buf[1..])?;
        Ok(Some((ErrorField { code, value }, end_pos)))
    }
}

#[derive(Debug)]
pub struct ErrorResponseBody {
    pub fields: Vec<ErrorField>,
}

impl Display for ErrorResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: ErrorResponse")?;
        for field in &self.fields {
            writeln!(f, "  Field: code = {}, value = {}", field.code, field.value)?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
enum ErrorResponseBodyParseError {
    #[error("invalid message length {0}. It can't be less than {1}")]
    LengthTooShort(usize, usize),

    #[error("invalid field: {0}")]
    InvalidField(#[from] ReadCStrError),
}

impl ErrorResponseBody {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<ErrorResponseBody>, ErrorResponseBodyParseError> {
        let mut body_buf = &buf[5..];
        if body_buf.len() < length - 4 {
            return Ok(None);
        }

        if length < 5 {
            buf.advance(length + 1);
            return Err(ErrorResponseBodyParseError::LengthTooShort(length, 5));
        }

        let mut fields = Vec::new();
        loop {
            let (field, end_pos) = match ErrorField::parse(body_buf)? {
                Some(res) => res,
                None => return Ok(None),
            };
            if field.code == 0 {
                break;
            }
            fields.push(field);
            body_buf = &body_buf[end_pos..];
        }
        Ok(Some(ErrorResponseBody { fields }))
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
                    ServerMessage::Authentication(ref auth_req) => match auth_req {
                        AuthenticationRequest::AuthenticationOk => {
                            *state = super::ProtocolState::StartupDone
                        }
                        AuthenticationRequest::AuthenticationKerberosV5 => todo!(),
                        AuthenticationRequest::AuthenticationCleartextPassword => todo!(),
                        AuthenticationRequest::AuthenticationMd5Password => todo!(),
                        AuthenticationRequest::AuthenticationGss => todo!(),
                        AuthenticationRequest::AuthenticationGssContinue => todo!(),
                        AuthenticationRequest::AuthenticationSspi => todo!(),
                        AuthenticationRequest::AuthenticationSasl(_) => {
                            *state = super::ProtocolState::AuthenticatingSasl
                        }
                        AuthenticationRequest::AuthenticationSaslContinue => todo!(),
                        AuthenticationRequest::AuthenticationSaslFinal => todo!(),
                    },
                    ServerMessage::Ssl(SslResponse { accepted }) => {
                        if accepted {
                            *state = super::ProtocolState::StartupDone
                        } else {
                            *state = super::ProtocolState::Initial
                        }
                    }
                    ServerMessage::Error(_) => {
                        if matches!(*state, super::ProtocolState::AuthenticatingSasl) {
                            *state = super::ProtocolState::Initial
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
