pub mod client;
pub mod server;

use std::{
    ffi::CStr,
    fmt::Display,
    sync::{Arc, Mutex},
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use thiserror::Error;

use self::{
    client::{FirstMessage, SubsequentMessage},
    server::{ServerMessage, SslResponse},
};

const MAX_ALLOWED_MESSAGE_LENGTH: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub tag: u8,
    pub length: i32,
}

#[derive(Error, Debug)]
enum HeaderParseError {
    #[error("invalid message length {0}. It can't be less than {1}")]
    LengthTooShort(usize, usize),
    #[error("invalid message length {0}. It can't be greater than {1}")]
    LengthTooLong(usize, usize),
}

impl Header {
    fn parse(buf: &mut BytesMut) -> Result<Option<Header>, HeaderParseError> {
        if buf.len() < 5 {
            return Ok(None);
        }

        // First byte contains the tag
        let tag = buf[0];

        // Bytes 1 to 4 contain the length of the message.
        let length = BigEndian::read_i32(&buf[1..5]) as usize;

        // Length includes its own four bytes as well so it shouldn't be less than 5
        if length < 4 {
            buf.advance(length + 1);
            return Err(HeaderParseError::LengthTooShort(length, 4));
        }

        // Check that the length is not too large to avoid a denial of
        // service attack where the proxy runs out of memory.
        if length > MAX_ALLOWED_MESSAGE_LENGTH {
            buf.advance(length + 1);
            return Err(HeaderParseError::LengthTooLong(
                length,
                MAX_ALLOWED_MESSAGE_LENGTH,
            ));
        }

        Ok(Some(Header {
            tag,
            length: length as i32,
        }))
    }
}

#[derive(Debug)]
pub struct CopyDataBody {
    data: Vec<u8>,
}

impl Display for CopyDataBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        writeln!(f, "  Type: CopyData")?;
        writeln!(f, "  Data: {:?}", self.data)
    }
}

#[derive(Error, Debug)]
enum CopyDataBodyParseError {
    #[error("invalid message length {0}. It can't be less than {1}")]
    LengthTooShort(usize, usize),
}

impl CopyDataBody {
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<CopyDataBody>, CopyDataBodyParseError> {
        let body_buf = &buf[5..];
        if length < 4 {
            buf.advance(length + 1);
            return Err(CopyDataBodyParseError::LengthTooShort(length, 4));
        }
        if body_buf.len() < length - 4 {
            return Ok(None);
        }
        let data = body_buf[..length - 4].to_vec();
        Ok(Some(CopyDataBody { data }))
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
    fn parse(
        length: usize,
        buf: &mut BytesMut,
    ) -> Result<Option<CopyDoneBody>, CopyDoneBodyParseError> {
        let body_buf = &buf[5..];
        if length < 4 {
            buf.advance(length + 1);
            return Err(CopyDoneBodyParseError::InvalidLength(length, 4));
        }
        if body_buf.len() < length - 4 {
            return Ok(None);
        }
        Ok(Some(CopyDoneBody))
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
    fn parse(buf: &[u8], header: Header) -> Option<UnknownMessageBody> {
        let data_length = header.length as usize - 4;
        if buf.len() < data_length {
            return None;
        }

        Some(UnknownMessageBody {
            header,
            bytes: buf[..data_length].to_vec(),
        })
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
                format!("c string is not null terminated"),
            ),
            ReadCStrError::NotUtf8Formatted => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("c string is utf8 formatted"),
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

#[derive(Debug, Clone, Copy)]
enum ProtocolState {
    Initial,
    Startup(StartupState),
    ReadyForQuery,
    SimpleQuery,
    //TODO: uncomment & use
    // ExtendedQuery,
    // FunctionCall,
    Copy(CopyMode),
}

#[derive(Debug, Clone, Copy)]
enum StartupState {
    Plaintext,
    Ssl,
    GssApi,
    Cancel,
}

#[derive(Debug, Clone, Copy)]
enum CopyMode {
    //TODO: uncomment & use
    // In,
    // Out,
    Both,
}

struct CurrentProtocolState {
    state_stack: Vec<ProtocolState>,
}

impl CurrentProtocolState {
    pub fn first_message(&mut self, message: &FirstMessage) {
        debug_assert!(matches!(self.peek(), ProtocolState::Initial));

        let state = match message {
            FirstMessage::StartupMessage(_) => ProtocolState::Startup(StartupState::Plaintext),
            FirstMessage::CancelRequest(_) => ProtocolState::Startup(StartupState::Cancel),
            FirstMessage::SslRequest => ProtocolState::Startup(StartupState::Ssl),
            FirstMessage::GssEncRequest => ProtocolState::Startup(StartupState::GssApi),
        };
        self.state_stack.push(state);
    }

    pub fn subsequent_message(&mut self, msg: &SubsequentMessage) {
        match msg {
            SubsequentMessage::Query(_) => self.state_stack.push(ProtocolState::SimpleQuery),
            SubsequentMessage::CopyData(_) => {}
            SubsequentMessage::Terminate => {
                self.state_stack.pop();
            }
            SubsequentMessage::Unknown(_) => {
                //No state transition for unknown message type
            }
        }
    }

    pub fn server_message(&mut self, msg: &ServerMessage) {
        match msg {
            ServerMessage::Authentication(req) => {
                debug_assert!(matches!(self.peek(), ProtocolState::Startup(_)));
                match req {
                    server::AuthenticationRequest::AuthenticationOk => {}
                    server::AuthenticationRequest::AuthenticationKerberosV5 => {}
                    server::AuthenticationRequest::AuthenticationCleartextPassword => {}
                    server::AuthenticationRequest::AuthenticationMd5Password => {}
                    server::AuthenticationRequest::AuthenticationGss => {}
                    server::AuthenticationRequest::AuthenticationGssContinue => {}
                    server::AuthenticationRequest::AuthenticationSspi => {}
                    server::AuthenticationRequest::AuthenticationSasl => {}
                    server::AuthenticationRequest::AuthenticationSaslContinue => {}
                    server::AuthenticationRequest::AuthenticationSaslFinal => {}
                }
            }
            ServerMessage::Ssl(SslResponse { accepted }) => {
                if *accepted {
                    self.state_stack.push(ProtocolState::ReadyForQuery);
                } else {
                    let old_state = self.state_stack.pop();
                    debug_assert!(matches!(
                        old_state,
                        Some(ProtocolState::Startup(StartupState::Ssl))
                    ))
                }
            }
            ServerMessage::ParameterStatus(_) => {}
            ServerMessage::BackendKeyData(_) => {}
            ServerMessage::ReadyForQuery(_) => {
                if matches!(self.peek(), ProtocolState::Startup(_)) {
                    self.state_stack.push(ProtocolState::ReadyForQuery);
                } else {
                    self.state_stack.pop();
                }
            }
            ServerMessage::RowDescription(_) => {}
            ServerMessage::CommandCompelte(_) => {}
            ServerMessage::DataRow(_) => {}
            ServerMessage::CopyData(_) => {}
            ServerMessage::CopyIn(_) => {}
            ServerMessage::CopyOut(_) => {}
            ServerMessage::CopyBoth(_) => {
                self.state_stack.push(ProtocolState::Copy(CopyMode::Both));
            }
            ServerMessage::CopyDone(_) => {}
            ServerMessage::Error(_) => {}
            ServerMessage::Unknown(_) => {}
        }
    }

    pub fn startup_done(&mut self) -> bool {
        match self.peek() {
            ProtocolState::Initial => false,
            ProtocolState::Startup(_) => false,
            ProtocolState::ReadyForQuery => true,
            ProtocolState::SimpleQuery => true,
            //TODO: uncomment & use
            // ProtocolState::ExtendedQuery => true,
            // ProtocolState::FunctionCall => true,
            ProtocolState::Copy(_) => true,
        }
    }

    pub fn expecting_ssl_response(&mut self) -> bool {
        matches!(self.peek(), ProtocolState::Startup(StartupState::Ssl))
    }

    fn peek(&mut self) -> ProtocolState {
        if self.state_stack.is_empty() {
            panic!("empty state stack");
        }
        self.state_stack[self.state_stack.len() - 1]
    }
}

pub fn create_decoders() -> (client::ClientMessageDecoder, server::ServerMessageDecoder) {
    let current_protocol_state = CurrentProtocolState {
        state_stack: vec![ProtocolState::Initial],
    };
    let current_protocol_state = Arc::new(Mutex::new(current_protocol_state));
    let client_msg_decoder = client::ClientMessageDecoder {
        current_protocol_state: Arc::clone(&current_protocol_state),
    };
    let server_msg_decoder = server::ServerMessageDecoder {
        current_protocol_state,
    };
    (client_msg_decoder, server_msg_decoder)
}
