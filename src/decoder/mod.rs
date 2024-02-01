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

        if buf.len() < length + 1 {
            return Ok(None);
        }

        Ok(Some(Header {
            tag,
            length: length as i32,
        }))
    }

    fn skip(&self) -> usize {
        self.length as usize + 1
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

impl CopyDataBody {
    fn parse(length: usize, buf: &[u8]) -> CopyDataBody {
        let data = buf[..length - 4].to_vec();
        CopyDataBody { data }
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
enum ProtocolState {
    Initial,
    NegotiatingSsl,
    StartupDone,
    AuthenticatingSasl(bool),
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
}

pub fn create_decoders() -> (client::ClientMessageDecoder, server::ServerMessageDecoder) {
    let protocol_state = Arc::new(Mutex::new(ProtocolState::Initial));
    let client_msg_decoder = client::ClientMessageDecoder {
        protocol_state: Arc::clone(&protocol_state),
    };
    let server_msg_decoder = server::ServerMessageDecoder { protocol_state };
    (client_msg_decoder, server_msg_decoder)
}
