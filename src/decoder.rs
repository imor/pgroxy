use std::ffi::CStr;

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use tokio_util::codec::Decoder;

pub struct MessageDecoder {
    startup_decoded: bool,
}

impl MessageDecoder {
    pub fn new() -> MessageDecoder {
        MessageDecoder {
            startup_decoded: false,
        }
    }
}

const MAX_ALLOWED_MESSAGE_LENGTH: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub enum Message {
    First(FirstMessage),
}

/// FirstMessage is the first message sent by a client to the server.
/// It contains length of the message in the first four bytes interpreted
/// as a big endian i32. The next four bytes contain the type again
/// interpreted as a big endian i32. The rest of the message varies
/// according to which type it is.
#[derive(Debug)]
pub enum FirstMessage {
    StartupMessage(StartupMessageBody),
    CancelRequest(CancelRequestBody),
    SslRequest,
    GssEncRequest,
}

const CANCEL_REQUEST_TYPE: i32 = 80877102;
const SSL_REQUEST_TYPE: i32 = 80877103;
const GSS_ENC_REQUEST_TYPE: i32 = 80877104;

impl FirstMessage {
    fn parse(src: &mut BytesMut) -> Result<Option<FirstMessage>, std::io::Error> {
        if src.len() < 4 {
            // Not enough data to read message length
            return Ok(None);
        }

        // First four bytes contain the length of the message.
        let length = BigEndian::read_i32(&src[..4]) as usize;

        if length < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length {}. It can't be less than 4", length),
            ));
        }

        // Check that the length is not too large to avoid a denial of
        // service attack where the proxy runs out of memory.
        if length > MAX_ALLOWED_MESSAGE_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", length),
            ));
        }

        if src.len() < length {
            // The full message has not yet arrived.
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            src.reserve(length - src.len());

            // We inform the Framed that we need more bytes to form the next
            // frame.
            return Ok(None);
        }

        let typ = BigEndian::read_i32(&src[4..8]);
        let res = match typ {
            CANCEL_REQUEST_TYPE => match CancelRequestBody::parse(length, src)? {
                Some(body) => Ok(Some(FirstMessage::CancelRequest(body))),
                None => Ok(None),
            },
            SSL_REQUEST_TYPE => Ok(Some(FirstMessage::SslRequest)),
            GSS_ENC_REQUEST_TYPE => Ok(Some(FirstMessage::GssEncRequest)),
            _ => match StartupMessageBody::parse(length, typ, src)? {
                Some(body) => Ok(Some(FirstMessage::StartupMessage(body))),
                None => Ok(None),
            },
        };

        // Use advance to modify src such that it no longer contains
        // this message.
        src.advance(length);
        res
    }
}

#[derive(Debug)]
pub struct StartupMessageBody {
    pub protocol_version: i32,
    pub parameters: Vec<String>, // TODO use pairs of parameters ie. Vec<(String, String)
}

impl StartupMessageBody {
    fn parse(
        length: usize,
        protocol_version: i32,
        src: &mut BytesMut,
    ) -> Result<Option<StartupMessageBody>, std::io::Error> {
        let mut param_start = 8;
        let mut parameters = Vec::new();
        loop {
            match CStr::from_bytes_until_nul(&src[param_start..]) {
                Ok(param) => {
                    param_start += param.to_bytes().len() + 1;
                    match param.to_str() {
                        Ok(param) => {
                            if param.is_empty() {}
                            parameters.push(param.to_string())
                        }
                        Err(_) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Invalid parameter in startup message: not valid utf-8 encoded",
                            ));
                        }
                    }
                    if param_start >= length - 1 {
                        if src[length - 1] != 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Invalid startup message: not null terminated",
                            ));
                        }
                        break;
                    }
                }
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid parameter in startup message: not null terminated",
                    ));
                }
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

impl CancelRequestBody {
    fn parse(
        length: usize,
        src: &mut BytesMut,
    ) -> Result<Option<CancelRequestBody>, std::io::Error> {
        if length != 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length {}. It should be 16", length),
            ));
        }
        if src.len() < 16 {
            src.reserve(length - src.len());
            return Ok(None);
        }
        Ok(Some(CancelRequestBody {
            process_id: BigEndian::read_i32(&src[8..12]),
            secret_key: BigEndian::read_i32(&src[12..16]),
        }))
    }
}

impl Decoder for MessageDecoder {
    type Item = Message;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.startup_decoded {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unimplemented",
            ));
        } else {
            match FirstMessage::parse(src)? {
                Some(msg) => {
                    self.startup_decoded = true;
                    Ok(Some(Message::First(msg)))
                }
                None => Ok(None),
            }
        }
    }
}
