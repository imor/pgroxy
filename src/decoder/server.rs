use std::{
    fmt::Display,
    sync::{Arc, Mutex},
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use thiserror::Error;
use tokio_util::codec::Decoder;

use super::{
    read_cstr, CopyDataBody, CopyDoneBody, CopyDoneBodyParseError, Header, ReadCStrError,
    NUM_HEADER_BYTES,
};

#[derive(Debug)]
pub enum ServerMessage {
    Authentication(AuthenticationRequest),
    Ssl(SslResponse),
    ParameterStatus(ParameterStatusBody),
    BackendKeyData(BackendKeyDataBody),
    ReadyForQuery(ReadyForQueryBody),
    RowDescription(RowDescriptionBody),
    CommandComplete(CommandCompleteBody),
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
            ServerMessage::CommandComplete(body) => write!(f, "{body}"),
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
            match Self::parse_header_and_message(buf) {
                Ok(msg) => match msg {
                    Some((msg, skip)) => {
                        buf.advance(skip);
                        Ok(Some(msg))
                    }
                    None => Ok(None),
                },
                Err((e, skip)) => {
                    buf.advance(skip);
                    Err(e)
                }
            }
        }
    }

    fn parse_header_and_message(
        buf: &mut BytesMut,
    ) -> Result<Option<(ServerMessage, usize)>, (ServerMessageParseError, usize)> {
        match super::Header::parse(buf) {
            Some(header) => Ok(Some(Self::parse_message(header, buf)?)),
            None => Ok(None),
        }
    }

    fn parse_message(
        header: Header,
        mut buf: &[u8],
    ) -> Result<(ServerMessage, usize), (ServerMessageParseError, usize)> {
        buf = &buf[NUM_HEADER_BYTES..];
        buf = &buf[..header.payload_length()];
        match header.tag {
            AUTHENTICATION_MESSAGE_TAG => {
                let auth_req = AuthenticationRequest::parse(buf)
                    .map_err(|e| (e.into(), header.msg_length()))?;
                Ok((ServerMessage::Authentication(auth_req), header.msg_length()))
            }
            PARAM_STATUS_MESSAGE_TAG => {
                let body =
                    ParameterStatusBody::parse(buf).map_err(|e| (e.into(), header.msg_length()))?;
                Ok((ServerMessage::ParameterStatus(body), header.msg_length()))
            }
            BACKEND_KEY_DATA_MESSAGE_TAG => {
                let body =
                    BackendKeyDataBody::parse(buf).map_err(|e| (e.into(), header.msg_length()))?;
                Ok((ServerMessage::BackendKeyData(body), header.msg_length()))
            }
            READY_FOR_QUERY_MESSAGE_TAG => {
                let body =
                    ReadyForQueryBody::parse(buf).map_err(|e| (e.into(), header.msg_length()))?;
                Ok((ServerMessage::ReadyForQuery(body), header.msg_length()))
            }
            ROW_DESCRIPTION_MESSAGE_TAG => {
                let body =
                    RowDescriptionBody::parse(buf).map_err(|e| (e.into(), header.msg_length()))?;
                Ok((ServerMessage::RowDescription(body), header.msg_length()))
            }
            COMMAND_COMPLETE_MESSAGE_TAG => {
                let body =
                    CommandCompleteBody::parse(buf).map_err(|e| (e.into(), header.msg_length()))?;
                Ok((ServerMessage::CommandComplete(body), header.msg_length()))
            }
            DATA_ROW_MESSAGE_TAG => {
                let body = DataRowBody::parse(buf).map_err(|e| (e.into(), header.msg_length()))?;
                Ok((ServerMessage::DataRow(body), header.msg_length()))
            }
            COPY_DATA_MESSAGE_TAG => {
                let body = CopyDataBody::parse(buf);
                Ok((ServerMessage::CopyData(body), header.msg_length()))
            }
            COPY_IN_MESSAGE_TAG => {
                let body =
                    CopyInResponseBody::parse(buf).map_err(|e| (e.into(), header.msg_length()))?;
                Ok((ServerMessage::CopyIn(body), header.msg_length()))
            }
            COPY_OUT_MESSAGE_TAG => {
                let body =
                    CopyOutResponseBody::parse(buf).map_err(|e| (e.into(), header.msg_length()))?;
                Ok((ServerMessage::CopyOut(body), header.msg_length()))
            }
            COPY_BOTH_MESSAGE_TAG => {
                let body = CopyBothResponseBody::parse(buf)
                    .map_err(|e| (e.into(), header.msg_length()))?;
                Ok((ServerMessage::CopyBoth(body), header.msg_length()))
            }
            COPY_DONE_MESSAGE_TAG => {
                let body = CopyDoneBody::parse(buf).map_err(|e| (e.into(), header.msg_length()))?;
                Ok((ServerMessage::CopyDone(body), header.msg_length()))
            }
            ERROR_RESPONSE_MESSAGE_TAG => {
                let body =
                    ErrorResponseBody::parse(buf).map_err(|e| (e.into(), header.msg_length()))?;
                Ok((ServerMessage::Error(body), header.msg_length()))
            }
            _ => {
                let body = super::UnknownMessageBody::parse(buf, header);
                Ok((ServerMessage::Unknown(body), header.msg_length()))
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
        writeln!(f)?;
        writeln!(f, "  Type: {typ}")
    }
}

#[derive(Error, Debug)]
enum AuthenticationRequestParseError {
    #[error("invalid message length {0}. It should be {1}")]
    InvalidLength(usize, usize),

    #[error("invalid message length {0}. It can't be smaller than {1}")]
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
    fn parse(buf: &[u8]) -> Result<AuthenticationRequest, AuthenticationRequestParseError> {
        if buf.len() < 4 {
            return Err(AuthenticationRequestParseError::LengthTooShort(
                buf.len(),
                4,
            ));
        }
        let typ = BigEndian::read_i32(buf);

        match typ {
            AUTHETICATION_OK_TYPE => {
                if buf.len() != 4 {
                    Err(AuthenticationRequestParseError::InvalidLength(buf.len(), 4))
                } else {
                    Ok(AuthenticationRequest::AuthenticationOk)
                }
            }
            AUTHETICATION_KERBEROS_TYPE => {
                if buf.len() != 4 {
                    Err(AuthenticationRequestParseError::InvalidLength(buf.len(), 4))
                } else {
                    Ok(AuthenticationRequest::AuthenticationKerberosV5)
                }
            }
            AUTHETICATION_CLEARTEXT_PWD_TYPE => {
                if buf.len() != 4 {
                    Err(AuthenticationRequestParseError::InvalidLength(buf.len(), 4))
                } else {
                    Ok(AuthenticationRequest::AuthenticationCleartextPassword)
                }
            }
            AUTHETICATION_MD5_PWD_TYPE => {
                if buf.len() != 8 {
                    Err(AuthenticationRequestParseError::InvalidLength(buf.len(), 8))
                } else {
                    Ok(AuthenticationRequest::AuthenticationMd5Password)
                }
            }
            AUTHETICATION_GSS_TYPE => {
                if buf.len() != 4 {
                    Err(AuthenticationRequestParseError::InvalidLength(buf.len(), 4))
                } else {
                    Ok(AuthenticationRequest::AuthenticationGss)
                }
            }
            AUTHETICATION_GSS_CONTINUE_TYPE => {
                if buf.len() < 4 {
                    Err(AuthenticationRequestParseError::LengthTooShort(
                        buf.len(),
                        4,
                    ))
                } else {
                    Ok(AuthenticationRequest::AuthenticationGssContinue)
                }
            }
            AUTHETICATION_SSPI_TYPE => {
                if buf.len() != 4 {
                    Err(AuthenticationRequestParseError::InvalidLength(buf.len(), 4))
                } else {
                    Ok(AuthenticationRequest::AuthenticationSspi)
                }
            }
            AUTHETICATION_SASL_TYPE => {
                if buf.len() < 4 {
                    Err(AuthenticationRequestParseError::LengthTooShort(
                        buf.len(),
                        4,
                    ))
                } else {
                    let body = SaslBody::parse(&buf[4..])?;
                    Ok(AuthenticationRequest::AuthenticationSasl(body))
                }
            }
            AUTHETICATION_SASL_CONTINUE_TYPE => {
                if buf.len() <= 4 {
                    Err(AuthenticationRequestParseError::LengthTooShort(
                        buf.len(),
                        4,
                    ))
                } else {
                    Ok(AuthenticationRequest::AuthenticationSaslContinue)
                }
            }
            AUTHETICATION_SASL_FINAL_TYPE => {
                if buf.len() < 4 {
                    Err(AuthenticationRequestParseError::LengthTooShort(
                        buf.len(),
                        4,
                    ))
                } else {
                    Ok(AuthenticationRequest::AuthenticationSaslFinal)
                }
            }
            typ => Err(AuthenticationRequestParseError::InvalidType(typ)),
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
    fn parse(buf: &[u8]) -> Result<SaslBody, SaslBodyParseError> {
        let mut mechanism_start = 0;
        let mut auth_mechanisms = Vec::new();
        loop {
            let (mechanism, end_pos) = super::read_cstr(&buf[mechanism_start..])?;
            auth_mechanisms.push(mechanism);
            mechanism_start += end_pos;
            if mechanism_start >= buf.len() {
                if buf[buf.len() - 1] != 0 {
                    return Err(SaslBodyParseError::NotNullTerminated);
                }
                break;
            }
        }
        Ok(SaslBody { auth_mechanisms })
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
    fn parse(buf: &[u8]) -> Result<ParameterStatusBody, ParameterStatusBodyParseError> {
        let (param_name, end_pos) = match super::read_cstr(buf) {
            Ok(res) => res,
            Err(e) => {
                return Err(ParameterStatusBodyParseError::InvalidParamName(e));
            }
        };
        let (param_value, _) = match super::read_cstr(&buf[end_pos..]) {
            Ok(res) => res,
            Err(e) => {
                return Err(ParameterStatusBodyParseError::InvalidParamValue(e));
            }
        };

        Ok(ParameterStatusBody {
            param_name,
            param_value,
        })
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
    fn parse(buf: &[u8]) -> Result<BackendKeyDataBody, BackendKeyDataBodyParseError> {
        if buf.len() != 8 {
            Err(BackendKeyDataBodyParseError::InvalidLength(buf.len(), 8))
        } else {
            Ok(BackendKeyDataBody {
                process_id: BigEndian::read_i32(&buf[0..4]),
                secret_key: BigEndian::read_i32(&buf[4..8]),
            })
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
    fn parse(buf: &[u8]) -> Result<ReadyForQueryBody, ReadyForQueryBodyParseError> {
        if buf.len() != 1 {
            Err(ReadyForQueryBodyParseError::InvalidLength(buf.len(), 1))
        } else {
            Ok(ReadyForQueryBody {
                transaction_status: buf[0],
            })
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

    #[error("invalid message length {0}. It can't be less than {1}")]
    LengthTooShort(usize, usize),
}

impl RowDescriptionField {
    fn parse(buf: &[u8]) -> Result<(RowDescriptionField, usize), RowDescriptionFieldParseError> {
        let (name, end_pos) = read_cstr(buf)?;
        let buf = &buf[end_pos..];

        if buf.len() < 18 {
            return Err(RowDescriptionFieldParseError::LengthTooShort(buf.len(), 18));
        }

        let oid = BigEndian::read_i32(buf);
        let attnum = BigEndian::read_i16(&buf[4..]);
        let typoid = BigEndian::read_i32(&buf[6..]);
        let typlen = BigEndian::read_i16(&buf[10..]);
        let typmod = BigEndian::read_i32(&buf[12..]);
        let format = BigEndian::read_i16(&buf[16..]);

        Ok((
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
        ))
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
    fn parse(mut buf: &[u8]) -> Result<RowDescriptionBody, RowDescriptionBodyParseError> {
        if buf.len() < 2 {
            return Err(RowDescriptionBodyParseError::LengthTooShort(buf.len(), 2));
        }

        let num_fields = BigEndian::read_i16(buf);
        if num_fields < 0 {
            return Err(RowDescriptionBodyParseError::InvalidNumFields(num_fields));
        }

        buf = &buf[2..];
        let mut fields = Vec::with_capacity(num_fields as usize);
        for _ in 0..num_fields {
            let (field, end_pos) = RowDescriptionField::parse(buf)?;
            fields.push(field);
            buf = &buf[end_pos..];
        }
        Ok(RowDescriptionBody { fields })
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
    #[error("invalid command tag: {0}")]
    InvalidCommandTag(#[from] ReadCStrError),

    #[error("trailing bytes after command tag")]
    TrailingBytes,
}

impl CommandCompleteBody {
    fn parse(buf: &[u8]) -> Result<CommandCompleteBody, CommandCompleteBodyParseError> {
        let (command_tag, end_pos) = read_cstr(buf)?;
        if end_pos != buf.len() {
            return Err(CommandCompleteBodyParseError::TrailingBytes);
        }
        Ok(CommandCompleteBody { command_tag })
    }
}

#[derive(Debug)]
pub struct DataRowColumn {
    pub is_null: bool,
    pub value: Vec<u8>,
}

#[derive(Error, Debug)]
enum DataRowColumnParseError {
    #[error("invalid length {0}")]
    InvalidLength(i32),
}

impl DataRowColumn {
    fn parse(mut buf: &[u8]) -> Result<(DataRowColumn, usize), DataRowColumnParseError> {
        let len = BigEndian::read_i32(buf);

        let mut end_pos = 4;
        // len is -1 when column is null
        if len == -1 {
            return Ok((
                DataRowColumn {
                    value: Vec::new(),
                    is_null: true,
                },
                end_pos,
            ));
        }

        if len < 0 || len as usize > buf.len() {
            return Err(DataRowColumnParseError::InvalidLength(len));
        }

        buf = &buf[4..];
        let value = buf[..len as usize].to_vec();
        end_pos += len as usize;

        Ok((
            DataRowColumn {
                value,
                is_null: false,
            },
            end_pos,
        ))
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
    fn parse(mut buf: &[u8]) -> Result<DataRowBody, DataRowBodyParseError> {
        if buf.len() < 6 {
            return Err(DataRowBodyParseError::LengthTooShort(buf.len(), 6));
        }

        let num_cols = BigEndian::read_i16(buf);
        if num_cols < 0 {
            return Err(DataRowBodyParseError::InvalidNumCols(num_cols));
        }

        buf = &buf[2..];
        let mut columns = Vec::with_capacity(num_cols as usize);
        for _ in 0..num_cols {
            let (column, end_pos) = DataRowColumn::parse(buf)?;
            columns.push(column);
            buf = &buf[end_pos..];
        }
        Ok(DataRowBody { columns })
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
    fn parse(mut buf: &[u8]) -> Result<CopyInResponseBody, CopyInResponseBodyParseError> {
        if buf.len() < 3 {
            return Err(CopyInResponseBodyParseError::LengthTooShort(buf.len(), 3));
        }

        let format = buf[0] as i8;
        buf = &buf[1..];

        let num_cols = BigEndian::read_i16(buf);
        if num_cols < 0 {
            return Err(CopyInResponseBodyParseError::InvalidNumCols(num_cols));
        }

        let mut col_formats = Vec::with_capacity(num_cols as usize);
        for _ in 0..num_cols {
            let format = BigEndian::read_i16(buf);
            col_formats.push(format);
            buf = &buf[2..];
        }

        Ok(CopyInResponseBody {
            format,
            col_formats,
        })
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
    fn parse(mut buf: &[u8]) -> Result<CopyOutResponseBody, CopyOutResponseBodyParseError> {
        if buf.len() < 3 {
            return Err(CopyOutResponseBodyParseError::LengthTooShort(buf.len(), 3));
        }

        let format = buf[0] as i8;
        buf = &buf[1..];

        let num_cols = BigEndian::read_i16(buf);
        if num_cols < 0 {
            return Err(CopyOutResponseBodyParseError::InvalidNumCols(num_cols));
        }

        let mut col_formats = Vec::with_capacity(num_cols as usize);
        for _ in 0..num_cols {
            let format = BigEndian::read_i16(buf);
            col_formats.push(format);
            buf = &buf[2..];
        }

        Ok(CopyOutResponseBody {
            format,
            col_formats,
        })
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
    fn parse(mut buf: &[u8]) -> Result<CopyBothResponseBody, CopyBothResponseBodyParseError> {
        if buf.len() < 3 {
            return Err(CopyBothResponseBodyParseError::LengthTooShort(buf.len(), 3));
        }

        let format = buf[0] as i8;
        buf = &buf[1..];

        let num_cols = BigEndian::read_i16(buf);
        if num_cols < 0 {
            return Err(CopyBothResponseBodyParseError::InvalidNumCols(num_cols));
        }

        let mut col_formats = Vec::with_capacity(num_cols as usize);
        for _ in 0..num_cols {
            let format = BigEndian::read_i16(buf);
            col_formats.push(format);
            buf = &buf[2..];
        }

        Ok(CopyBothResponseBody {
            format,
            col_formats,
        })
    }
}

#[derive(Debug)]
pub struct ErrorField {
    pub code: u8,
    pub value: String,
}

impl ErrorField {
    fn parse(buf: &[u8]) -> Result<(ErrorField, usize), ErrorResponseBodyParseError> {
        if buf.len() < 1 {
            return Err(ErrorResponseBodyParseError::LengthTooShort(buf.len(), 1));
        }

        let code = buf[0];
        if code == 0 {
            return Ok((
                ErrorField {
                    code: 0,
                    value: "".to_string(),
                },
                1,
            ));
        }
        let (value, end_pos) = read_cstr(&buf[1..])?;
        Ok((ErrorField { code, value }, end_pos))
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
    fn parse(mut buf: &[u8]) -> Result<ErrorResponseBody, ErrorResponseBodyParseError> {
        let mut fields = Vec::new();
        loop {
            let (field, end_pos) = ErrorField::parse(buf)?;
            if field.code == 0 {
                break;
            }
            fields.push(field);
            buf = &buf[end_pos..];
        }
        Ok(ErrorResponseBody { fields })
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
                        AuthenticationRequest::AuthenticationKerberosV5 => {}
                        AuthenticationRequest::AuthenticationCleartextPassword => {}
                        AuthenticationRequest::AuthenticationMd5Password => {}
                        AuthenticationRequest::AuthenticationGss => {}
                        AuthenticationRequest::AuthenticationGssContinue => {}
                        AuthenticationRequest::AuthenticationSspi => {}
                        AuthenticationRequest::AuthenticationSasl(_) => {
                            *state = super::ProtocolState::AuthenticatingSasl(false)
                        }
                        AuthenticationRequest::AuthenticationSaslContinue => {}
                        AuthenticationRequest::AuthenticationSaslFinal => {}
                    },
                    ServerMessage::Ssl(SslResponse { accepted }) => {
                        if accepted {
                            *state = super::ProtocolState::StartupDone
                        } else {
                            *state = super::ProtocolState::Initial
                        }
                    }
                    ServerMessage::Error(_) => {
                        if matches!(*state, super::ProtocolState::AuthenticatingSasl(_)) {
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
