use std::{
    ffi::CStr,
    sync::{Arc, Mutex},
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use tokio_util::codec::Decoder;

#[derive(Debug)]
pub enum ClientMessage {
    First(FirstMessage),
    Subsequent(SubsequentMessage),
}

#[derive(Debug)]
pub enum SubsequentMessage {
    Query(QueryBody),
    Unknown(super::UnknownMessageBody),
}

const QUERY_MESSAGE_TAG: u8 = b'Q';

impl SubsequentMessage {
    fn parse(buf: &mut BytesMut) -> Result<Option<SubsequentMessage>, std::io::Error> {
        match super::Header::parse(buf)? {
            Some(header) => {
                let res = match header.tag {
                    QUERY_MESSAGE_TAG => {
                        match QueryBody::parse(header.length as usize, &buf[5..])? {
                            Some(query_body) => Ok(Some(SubsequentMessage::Query(query_body))),
                            None => Ok(None),
                        }
                    }
                    _ => match super::UnknownMessageBody::parse(&buf[5..], header)? {
                        Some(body) => Ok(Some(SubsequentMessage::Unknown(body))),
                        None => Ok(None),
                    },
                };
                // eprintln!("Advancing over {} bytes", header.length + 1);
                buf.advance(header.length as usize + 1);
                res
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug)]
pub struct QueryBody {
    pub query: String,
}

impl QueryBody {
    fn parse(length: usize, buf: &[u8]) -> Result<Option<QueryBody>, std::io::Error> {
        if length <= 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length {length} for Query message. It should be at least 4"),
            ));
        }

        match CStr::from_bytes_with_nul(buf) {
            Ok(query) => match query.to_str() {
                Ok(query) => Ok(Some(QueryBody {
                    query: query.to_string(),
                })),
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid query. Not valid utf-8: {e:?}"),
                )),
            },
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid query. Not null terminated: {e:?}"),
            )),
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

const CANCEL_REQUEST_TYPE: i32 = 80877102;
const SSL_REQUEST_TYPE: i32 = 80877103;
const GSS_ENC_REQUEST_TYPE: i32 = 80877104;

impl FirstMessage {
    fn parse(buf: &mut BytesMut) -> Result<Option<FirstMessage>, std::io::Error> {
        if buf.len() < 4 {
            // Not enough data to read message length
            return Ok(None);
        }

        // First four bytes contain the length of the message.
        let length = BigEndian::read_i32(&buf[..4]) as usize;

        // Length includes its own four bytes as well so it shouldn't be less than 4
        if length < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length {length}. It can't be less than 4"),
            ));
        }

        // Check that the length is not too large to avoid a denial of
        // service attack where the proxy runs out of memory.
        if length > super::MAX_ALLOWED_MESSAGE_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Message of length {length} is too large."),
            ));
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
                None => Ok(None),
            },
            SSL_REQUEST_TYPE => Ok(Some(FirstMessage::SslRequest)),
            GSS_ENC_REQUEST_TYPE => Ok(Some(FirstMessage::GssEncRequest)),
            _ => match StartupMessageBody::parse(length, typ, buf)? {
                Some(body) => Ok(Some(FirstMessage::StartupMessage(body))),
                None => Ok(None),
            },
        };

        // Use advance to modify buf such that it no longer contains
        // this message.
        // eprintln!("Advancing over {length} bytes");
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
    fn parse(
        length: usize,
        protocol_version: i32,
        buf: &[u8],
    ) -> Result<Option<StartupMessageBody>, std::io::Error> {
        let mut param_start = 8;
        let mut parameters = Vec::new();
        loop {
            match CStr::from_bytes_until_nul(&buf[param_start..]) {
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
                        if buf[length - 1] != 0 {
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
        buf: &mut BytesMut,
    ) -> Result<Option<CancelRequestBody>, std::io::Error> {
        if length != 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length {length}. It should be 16"),
            ));
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
            match SubsequentMessage::parse(buf)? {
                Some(msg) => Ok(Some(ClientMessage::Subsequent(msg))),
                None => Ok(None),
            }
        } else {
            match FirstMessage::parse(buf)? {
                Some(msg) => {
                    match msg {
                        FirstMessage::SslRequest => {
                            *state = super::ProtocolState::SslRequestSent;
                        }
                        _ => {}
                    }
                    Ok(Some(ClientMessage::First(msg)))
                }
                None => Ok(None),
            }
        }
    }
}
