pub mod client;
pub mod server;

use std::{
    ffi::CStr,
    sync::{Arc, Mutex},
};

use byteorder::{BigEndian, ByteOrder};

const MAX_ALLOWED_MESSAGE_LENGTH: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub tag: u8,
    pub length: i32,
}

impl Header {
    fn parse(buf: &[u8]) -> Result<Option<Header>, std::io::Error> {
        if buf.len() < 5 {
            return Ok(None);
        }

        // First byte contains the tag
        let tag = buf[0];

        // Bytes 1 to 4 contain the length of the message.
        let length = BigEndian::read_i32(&buf[1..5]) as usize;

        // Length includes its own four bytes as well so it shouldn't be less than 5
        if length < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length {length}. It can't be less than 4"),
            ));
        }

        // Check that the length is not too large to avoid a denial of
        // service attack where the proxy runs out of memory.
        if length > MAX_ALLOWED_MESSAGE_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Message of length {length} is too large."),
            ));
        }

        Ok(Some(Header {
            tag,
            length: length as i32,
        }))
    }
}

#[derive(Debug)]
pub struct UnknownMessageBody {
    pub header: Header,
    pub bytes: Vec<u8>,
}

impl UnknownMessageBody {
    fn parse(buf: &[u8], header: Header) -> Result<Option<UnknownMessageBody>, std::io::Error> {
        let data_length = header.length as usize - 4;
        if buf.len() < data_length {
            return Ok(None);
        }

        Ok(Some(UnknownMessageBody {
            header,
            bytes: buf[..data_length].to_vec(),
        }))
    }
}

enum ReadCStrResult {
    NotNullTerminated,
    NotUtf8Formatted,
}

impl From<ReadCStrResult> for std::io::Error {
    fn from(value: ReadCStrResult) -> Self {
        match value {
            ReadCStrResult::NotNullTerminated => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("c string is not null terminated"),
            ),
            ReadCStrResult::NotUtf8Formatted => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("c string is utf8 formatted"),
            ),
        }
    }
}

fn read_cstr(buf: &[u8]) -> Result<(String, usize), ReadCStrResult> {
    match buf.iter().position(|b| *b == b'\0') {
        Some(null_pos) => {
            let cstr = unsafe { CStr::from_bytes_with_nul_unchecked(&buf[..(null_pos + 1)]) };
            match cstr.to_str() {
                Ok(str) => Ok((str.to_string(), null_pos + 1)),
                Err(_) => Err(ReadCStrResult::NotUtf8Formatted),
            }
        }
        None => Err(ReadCStrResult::NotNullTerminated),
    }
}

#[derive(Clone, Copy)]
enum ProtocolState {
    Initial,
    SslRequestSent,
    SslAccepted,
    SslRejected,
    AuthenticationOk,
}

impl ProtocolState {
    pub fn startup_done(&self) -> bool {
        match self {
            ProtocolState::Initial => false,
            ProtocolState::SslRequestSent => false,
            ProtocolState::SslAccepted => true,
            ProtocolState::SslRejected => false,
            ProtocolState::AuthenticationOk => true,
        }
    }

    pub fn expecting_ssl_response(&self) -> bool {
        matches!(self, ProtocolState::SslRequestSent)
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
