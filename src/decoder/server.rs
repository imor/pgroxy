use std::sync::{Arc, Mutex};

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use tokio_util::codec::Decoder;

use super::{read_cstr, HeaderParseError, ReadCStrError};

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
    Error(ErrorResponseBody),
    Unknown(super::UnknownMessageBody),
}

enum ServerMessageParseError {
    Header(HeaderParseError),
    Ssl(SslResponseParseError),
    Authentication(AuthenticationRequestParseError),
    ParamStatus(ParameterStatusBodyParseError),
    BackendKeyData(BackendKeyDataBodyParseError),
    RowDescription(RowDescriptionBodyParseError),
    CommandComplete(CommandCompleteBodyParseError),
    DataRow(DataRowBodyParseError),
    Error(ErrorResponseBodyParseError),
    ReadyForQuery(ReadyForQueryBodyParseError),
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

impl From<ReadyForQueryBodyParseError> for ServerMessageParseError {
    fn from(value: ReadyForQueryBodyParseError) -> Self {
        ServerMessageParseError::ReadyForQuery(value)
    }
}

impl From<RowDescriptionBodyParseError> for ServerMessageParseError {
    fn from(value: RowDescriptionBodyParseError) -> Self {
        ServerMessageParseError::RowDescription(value)
    }
}

impl From<CommandCompleteBodyParseError> for ServerMessageParseError {
    fn from(value: CommandCompleteBodyParseError) -> Self {
        ServerMessageParseError::CommandComplete(value)
    }
}

impl From<DataRowBodyParseError> for ServerMessageParseError {
    fn from(value: DataRowBodyParseError) -> Self {
        ServerMessageParseError::DataRow(value)
    }
}

impl From<ErrorResponseBodyParseError> for ServerMessageParseError {
    fn from(value: ErrorResponseBodyParseError) -> Self {
        ServerMessageParseError::Error(value)
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
            ServerMessageParseError::ReadyForQuery(e) => e.into(),
            ServerMessageParseError::RowDescription(e) => e.into(),
            ServerMessageParseError::CommandComplete(e) => e.into(),
            ServerMessageParseError::DataRow(e) => e.into(),
            ServerMessageParseError::Error(e) => e.into(),
        }
    }
}

const AUTHENTICATION_MESSAGE_TAG: u8 = b'R';
const PARAM_STATUS_MESSAGE_TAG: u8 = b'S';
const BACKEND_KEY_DATA_MESSAGE_TAG: u8 = b'K';
const READY_FOR_QUERY_MESSAGE_TAG: u8 = b'Z';
const ROW_DESCRIPTION_MESSAGE_TAG: u8 = b'T';
const COMMAND_COMPLETE_MESSAGE_TAG: u8 = b'C';
const DATA_ROW_MESSAGE_TAG: u8 = b'D';
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
                                None => {
                                    return Ok(None);
                                }
                            }
                        }
                        PARAM_STATUS_MESSAGE_TAG => {
                            match ParameterStatusBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(ServerMessage::ParameterStatus(body))),
                                None => {
                                    return Ok(None);
                                }
                            }
                        }
                        BACKEND_KEY_DATA_MESSAGE_TAG => {
                            match BackendKeyDataBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(ServerMessage::BackendKeyData(body))),
                                None => {
                                    return Ok(None);
                                }
                            }
                        }
                        READY_FOR_QUERY_MESSAGE_TAG => {
                            match ReadyForQueryBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::ReadyForQuery(body))),
                                None => {
                                    return Ok(None);
                                }
                            }
                        }
                        ROW_DESCRIPTION_MESSAGE_TAG => {
                            match RowDescriptionBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::RowDescription(body))),
                                None => {
                                    return Ok(None);
                                }
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
                        ERROR_RESPONSE_MESSAGE_TAG => {
                            match ErrorResponseBody::parse(header.length as usize, buf)? {
                                Some(body) => Ok(Some(Self::Error(body))),
                                None => {
                                    return Ok(None);
                                }
                            }
                        }
                        _ => match super::UnknownMessageBody::parse(&buf[5..], header) {
                            Some(body) => Ok(Some(ServerMessage::Unknown(body))),
                            None => {
                                return Ok(None);
                            }
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
                format!(
                    "Invalid BackendKeyDataBody message length {actual}. It should be {expected}"
                ),
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

#[derive(Debug)]
pub struct ReadyForQueryBody {
    pub transaction_status: u8,
}

enum ReadyForQueryBodyParseError {
    InvalidLength(usize, usize),
}

impl From<ReadyForQueryBodyParseError> for std::io::Error {
    fn from(value: ReadyForQueryBodyParseError) -> Self {
        match value {
            ReadyForQueryBodyParseError::InvalidLength(expected, actual) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid ReadyForQuery message length {actual}. It should be {expected}"),
            ),
        }
    }
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
        let res = if length != 5 {
            buf.advance(length + 1);
            Err(ReadyForQueryBodyParseError::InvalidLength(5, length))
        } else {
            Ok(Some(ReadyForQueryBody {
                transaction_status: body_buf[0],
            }))
        };
        res
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

enum RowDescriptionFieldParseError {
    InvalidName(ReadCStrError),
}

impl From<ReadCStrError> for RowDescriptionFieldParseError {
    fn from(value: ReadCStrError) -> Self {
        RowDescriptionFieldParseError::InvalidName(value)
    }
}

impl RowDescriptionField {
    fn parse(
        buf: &[u8],
    ) -> Result<Option<(RowDescriptionField, usize)>, RowDescriptionFieldParseError> {
        //TODO: advance before early return due to error
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

enum RowDescriptionBodyParseError {
    LengthTooShort(usize, usize),
    InvalidNumFields(i16),
    InvalidField(RowDescriptionFieldParseError),
}

impl From<RowDescriptionBodyParseError> for std::io::Error {
    fn from(value: RowDescriptionBodyParseError) -> Self {
        match value {
            RowDescriptionBodyParseError::LengthTooShort(length, limit) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid RowDescription message length {length}. It should be at least {limit}"
                ),
            ),
            RowDescriptionBodyParseError::InvalidNumFields(num_fields) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid number of fields {num_fields} in RowDescription message"),
            ),
            RowDescriptionBodyParseError::InvalidField(_) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid field in RowDescription message"),
            ),
        }
    }
}

impl From<RowDescriptionFieldParseError> for RowDescriptionBodyParseError {
    fn from(value: RowDescriptionFieldParseError) -> Self {
        RowDescriptionBodyParseError::InvalidField(value)
    }
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
            let (field, end_pos) = match RowDescriptionField::parse(body_buf)? {
                Some(res) => res,
                None => return Ok(None),
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

enum CommandCompleteBodyParseError {
    LengthTooShort(usize, usize),
    InvalidCommandTag(ReadCStrError),
}

impl From<CommandCompleteBodyParseError> for std::io::Error {
    fn from(value: CommandCompleteBodyParseError) -> Self {
        match value {
            CommandCompleteBodyParseError::LengthTooShort(length, limit) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid CommandComplete message length {length}. It should be at least {limit}"
                ),
            ),
            CommandCompleteBodyParseError::InvalidCommandTag(e) => e.into(),
        }
    }
}

impl From<ReadCStrError> for CommandCompleteBodyParseError {
    fn from(value: ReadCStrError) -> Self {
        CommandCompleteBodyParseError::InvalidCommandTag(value)
    }
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

struct DataRowColumnParseError(i32);

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
            //TODO: advance before early return due to error
            return Err(DataRowColumnParseError(len));
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

enum DataRowBodyParseError {
    LengthTooShort(usize, usize),
    InvalidNumCols(i16),
    InvalidColumnLength(DataRowColumnParseError),
}

impl From<DataRowBodyParseError> for std::io::Error {
    fn from(value: DataRowBodyParseError) -> Self {
        match value {
            DataRowBodyParseError::LengthTooShort(length, limit) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid DataRow message length {length}. It should be at least {limit}"),
            ),
            DataRowBodyParseError::InvalidNumCols(num_cols) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid number of columns {num_cols} in DataRow message"),
            ),
            DataRowBodyParseError::InvalidColumnLength(DataRowColumnParseError(length)) => {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid column length {length} in DataRow message"),
                )
            }
        }
    }
}

impl From<DataRowColumnParseError> for DataRowBodyParseError {
    fn from(value: DataRowColumnParseError) -> Self {
        DataRowBodyParseError::InvalidColumnLength(value)
    }
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
            let (column, end_pos) = match DataRowColumn::parse(body_buf)? {
                Some(res) => res,
                None => return Ok(None),
            };
            columns.push(column);
            body_buf = &body_buf[end_pos..];
        }
        Ok(Some(DataRowBody { columns }))
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

enum ErrorResponseBodyParseError {
    LengthTooShort(usize, usize),
    InvalidField(ReadCStrError),
}

impl From<ErrorResponseBodyParseError> for std::io::Error {
    fn from(value: ErrorResponseBodyParseError) -> Self {
        match value {
            ErrorResponseBodyParseError::LengthTooShort(length, limit) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length {length}. It should be greater than {limit}"),
            ),
            ErrorResponseBodyParseError::InvalidField(e) => e.into(),
        }
    }
}

impl From<ReadCStrError> for ErrorResponseBodyParseError {
    fn from(value: ReadCStrError) -> Self {
        ErrorResponseBodyParseError::InvalidField(value)
    }
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
            let (field, end_pos) = match ErrorField::parse(&body_buf)? {
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
