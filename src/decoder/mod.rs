pub mod client;
mod server;

use std::sync::{Arc, Mutex};

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use tokio_util::codec::Decoder;

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
pub enum ServerMessage {
    Authentication(AuthenticationRequest),
    Ssl(SslResponse),
    Unknown(UnknownMessageBody),
}

const AUTHENTICATION_MESSAGE_TAG: u8 = b'R';

impl ServerMessage {
    fn parse(
        buf: &mut BytesMut,
        expecting_ssl_response: bool,
    ) -> Result<Option<ServerMessage>, std::io::Error> {
        if expecting_ssl_response {
            match SslResponse::parse(buf)? {
                Some(msg) => Ok(Some(ServerMessage::Ssl(msg))),
                None => Ok(None),
            }
        } else {
            match Header::parse(buf)? {
                Some(header) => {
                    let res = match header.tag {
                        AUTHENTICATION_MESSAGE_TAG => {
                            match AuthenticationRequest::parse(header.length as usize, &buf[5..])? {
                                Some(auth_req) => Ok(Some(ServerMessage::Authentication(auth_req))),
                                None => Ok(None),
                            }
                        }
                        _ => match UnknownMessageBody::parse(&buf[5..], header)? {
                            Some(body) => Ok(Some(ServerMessage::Unknown(body))),
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
    fn parse(length: usize, buf: &[u8]) -> Result<Option<AuthenticationRequest>, std::io::Error> {
        if buf.len() < 4 {
            return Ok(None);
        }

        let typ = BigEndian::read_i32(buf);

        match typ {
            AUTHETICATION_OK_TYPE => {
                if length != 8 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid length {length} for AuthenticationOk message. It should be 8"
                        ),
                    ))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationOk))
                }
            }
            AUTHETICATION_KERBEROS_TYPE => {
                if length != 8 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid length {length} for AuthenticationKererosV5 message. It should be 8"
                        ),
                    ))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationKerberosV5))
                }
            }
            AUTHETICATION_CLEARTEXT_PWD_TYPE => {
                if length != 8 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid length {length} for AuthenticationCleartextPassword message. It should be 8"
                        ),
                    ))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationCleartextPassword))
                }
            }
            AUTHETICATION_MD5_PWD_TYPE => {
                if length != 12 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid length {length} for AuthenticationMd5Password message. It should be 12"
                        ),
                    ))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationMd5Password))
                }
            }
            AUTHETICATION_GSS_TYPE => {
                if length != 8 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid length {length} for AuthenticationGss message. It should be 8"
                        ),
                    ))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationGss))
                }
            }
            AUTHETICATION_GSS_CONTINUE_TYPE => {
                if length <= 8 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid length {length} for AuthenticationGssContinue message. It should be greater than 8"
                        ),
                    ))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationGssContinue))
                }
            }
            AUTHETICATION_SSPI_TYPE => {
                if length != 8 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid length {length} for AuthenticationSspi message. It should be 8"
                        ),
                    ))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationSspi))
                }
            }
            AUTHETICATION_SASL_TYPE => {
                if length <= 8 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid length {length} for AuthenticationSasl message. It should be greater than 8"
                        ),
                    ))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationSasl))
                }
            }
            AUTHETICATION_SASL_CONTINUE_TYPE => {
                if length <= 8 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid length {length} for AuthenticationSaslContinue message. It should be greater than 8"
                        ),
                    ))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationSaslContinue))
                }
            }
            AUTHETICATION_SASL_FINAL_TYPE => {
                if length <= 8 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid length {length} for AuthenticationSaslFinal message. It should be greater than 8"
                        ),
                    ))
                } else {
                    Ok(Some(AuthenticationRequest::AuthenticationSaslFinal))
                }
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid length {length} for AuthenticationOk message. It should be 6"),
            )),
        }
    }
}

#[derive(Debug)]
pub struct SslResponse {
    accepted: bool,
}

impl SslResponse {
    fn parse(buf: &mut BytesMut) -> Result<Option<SslResponse>, std::io::Error> {
        if buf.len() < 1 {
            return Ok(None);
        }

        let byte = buf[0];
        let res = match byte {
            b'S' => Ok(Some(SslResponse { accepted: true })),
            b'N' => Ok(Some(SslResponse { accepted: false })),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid SslResponse byte: {byte}"),
            )),
        };
        // eprintln!("Advancing over 1 bytes");
        buf.advance(1);
        res
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

pub struct ServerMessageDecoder {
    protocol_state: Arc<Mutex<ProtocolState>>,
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
                        *state = ProtocolState::AuthenticationOk
                    }
                    ServerMessage::Ssl(SslResponse { accepted }) => {
                        if accepted {
                            *state = ProtocolState::SslAccepted
                        } else {
                            *state = ProtocolState::SslRejected
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

pub fn create_decoders() -> (client::ClientMessageDecoder, ServerMessageDecoder) {
    let protocol_state = Arc::new(Mutex::new(ProtocolState::Initial));
    let client_msg_decoder = client::ClientMessageDecoder {
        protocol_state: Arc::clone(&protocol_state),
    };
    let server_msg_decoder = ServerMessageDecoder { protocol_state };
    (client_msg_decoder, server_msg_decoder)
}
