mod decoder;

use std::fmt::Display;
use std::sync::atomic::AtomicU16;

use bytes::BytesMut;
use clap::Parser;
use decoder::client::{ClientMessage, FirstMessage};
use decoder::server::{DataRowBodyFormatter, ServerMessage};
use decoder::{client::ClientMessageDecoder, server::ServerMessageDecoder};
use futures::FutureExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_util::codec::Decoder;

use crate::decoder::create_decoders;

trait HalfSession {
    fn bytes_copied(&mut self, bytes: &[u8]);
    fn connection_closed(&self);
    fn cancel_requested(&self);
}

#[derive(Clone)]
enum SessionId {
    Number(u16),
    NameAndNumber(String, u16),
}

impl SessionId {
    fn new() -> Self {
        let id = LAST_SESSION_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        SessionId::Number(id)
    }

    fn set_name(&mut self, name: String) {
        match self {
            SessionId::Number(number) => {
                *self = SessionId::NameAndNumber(name, *number);
            }
            SessionId::NameAndNumber(_, number) => {
                *self = SessionId::NameAndNumber(name, *number);
            }
        }
    }
}

impl Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionId::Number(id) => write!(f, "{id}"),
            SessionId::NameAndNumber(name, number) => write!(f, "{number}:{name}"),
        }
    }
}

struct ClientToUpstreamSession {
    buf: BytesMut,
    decoder: ClientMessageDecoder,
    total_bytes_copied: u64,
    session_id: SessionId,
}

const APPLICATION_NAME_PARAM: &str = "application_name";

impl HalfSession for ClientToUpstreamSession {
    fn bytes_copied(&mut self, bytes: &[u8]) {
        self.total_bytes_copied += bytes.len() as u64;
        self.buf.extend_from_slice(bytes);
        // println!("→ BYTES: {:?}", &self.buf[..]);

        loop {
            let message = self.decoder.decode(&mut self.buf);

            match message {
                Ok(Some(msg)) => {
                    if let ClientMessage::First(FirstMessage::StartupMessage(ref startup_msg)) = msg
                    {
                        for pair in startup_msg.parameters.chunks(2) {
                            if pair[0] == APPLICATION_NAME_PARAM {
                                self.session_id.set_name(pair[1].to_string());
                            }
                        }
                    }
                    println!("→ [{}] {msg}", self.session_id)
                }
                Ok(None) => {
                    break;
                }
                Err(e) => eprintln!("→ [{}] error decoding message: {e:?}", self.session_id),
            }
        }
    }

    fn connection_closed(&self) {
        println!("× [{}] Client closed the connection", self.session_id);
    }

    fn cancel_requested(&self) {
        println!("× [{}] Closing connection from client", self.session_id);
    }
}

struct UpstreamToClientSession {
    buf: BytesMut,
    decoder: ServerMessageDecoder,
    total_bytes_copied: u64,
    session_id: SessionId,
}

impl HalfSession for UpstreamToClientSession {
    fn bytes_copied(&mut self, bytes: &[u8]) {
        self.total_bytes_copied += bytes.len() as u64;
        self.buf.extend_from_slice(bytes);
        // println!("← BYTES: {:?}", &self.buf[..]);

        loop {
            let message = self.decoder.decode(&mut self.buf);

            match message {
                Ok(Some(msg)) => match msg {
                    ServerMessage::DataRow(ref row) => {
                        let formatter = DataRowBodyFormatter {
                            data_row_body: row,
                            row_description_body: self.decoder.row_description(),
                        };
                        println!("← [{}] {formatter}", self.session_id)
                    }
                    ServerMessage::ParameterStatus(ref param_status) => {
                        if param_status.param_name == APPLICATION_NAME_PARAM {
                            self.session_id.set_name(param_status.param_value.clone());
                        }
                        println!("← [{}] {param_status}", self.session_id)
                    }
                    _ => {
                        println!("← [{}] {msg}", self.session_id)
                    }
                },
                Ok(None) => {
                    break;
                }
                Err(e) => eprintln!("← [{}] error decoding message: {e:?}", self.session_id),
            }
        }
    }

    fn connection_closed(&self) {
        println!("× [{}] Upstream closed the connection", self.session_id);
    }

    fn cancel_requested(&self) {
        println!("× [{}] Closing connection to upstream", self.session_id);
    }
}

static LAST_SESSION_ID: AtomicU16 = AtomicU16::new(0);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Addresses to listen at in the <ip>:<port> format
    #[arg(short, long, name = "Listen Address", required = true)]
    listen: Vec<String>,

    /// Upstream address to connect to in the <ip>:<port> format
    #[arg(short, long, name = "Upstream Address")]
    connect: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.listen.is_empty() {
        eprintln!("At least one listen address must be specified");
        return Ok(());
    }

    let Args { listen, connect } = args;

    let mut handles = vec![];
    for addr in &listen {
        let listener = TcpListener::bind(addr).await?;
        println!("👂Listening on {addr}");
        let connect = connect.clone();
        let result = tokio::spawn(async {
            handle_connection(listener, connect)
                .await
                .expect("failed to handle connection for address {addr}");
        });
        handles.push(result);
    }

    for handle in handles {
        handle.await?;
    }

    Ok(())
}

async fn handle_connection(
    listener6: TcpListener,
    upstream_addr: String,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let (mut client, client_addr) = listener6.accept().await?;
        let session_id = SessionId::new();
        println!("→ [{session_id}] Received a client connection from {client_addr}");

        let upstream_addr = upstream_addr.to_string();

        tokio::spawn(async move {
            let mut upstream = match TcpStream::connect(upstream_addr).await {
                Ok(upstream) => upstream,
                Err(e) => {
                    eprintln!("× [{session_id}] failed to connect to upstream; err = {e:?}");
                    return;
                }
            };

            let (mut client_reader, mut client_writer) = client.split();
            let (mut upstream_reader, mut upstream_writer) = upstream.split();

            let (cancel_sender, _) = broadcast::channel::<()>(1);

            let (client_msg_decoder, server_msg_decoder) = create_decoders();

            let mut client_to_upstream_session = ClientToUpstreamSession {
                buf: BytesMut::new(),
                decoder: client_msg_decoder,
                total_bytes_copied: 0,
                session_id: session_id.clone(),
            };
            let mut upstream_to_client_session = UpstreamToClientSession {
                buf: BytesMut::new(),
                decoder: server_msg_decoder,
                total_bytes_copied: 0,
                session_id: session_id.clone(),
            };

            let (client_res, upstream_res) = tokio::join! {
                copy_bytes(&mut client_reader, &mut upstream_writer,
                        &mut client_to_upstream_session, cancel_sender.subscribe())
                    .then(|r| { let _ = cancel_sender.send(()); async { r } }),
                copy_bytes(&mut upstream_reader, &mut client_writer,
                        &mut upstream_to_client_session, cancel_sender.subscribe())
                    .then(|r| { let _ = cancel_sender.send(()); async { r } }),
            };

            println!(
                "→ [{session_id}] copied total {} bytes in this session",
                client_to_upstream_session.total_bytes_copied
            );
            println!(
                "← [{session_id}] copied total {} bytes in this session",
                upstream_to_client_session.total_bytes_copied
            );
            if let Err(e) = client_res {
                eprintln!(
                    "× [{session_id}] Error while copying bytes from client to upstream; err = {e:?}"
                );
            }
            if let Err(e) = upstream_res {
                eprintln!(
                    "× [{session_id}] Error while copying bytes from upstream to client; err = {e:?}"
                );
            }
        });
    }
}

async fn copy_bytes<R, W, S>(
    reader: &mut R,
    writer: &mut W,
    session: &mut S,
    mut cancel_receiver: broadcast::Receiver<()>,
) -> tokio::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    S: HalfSession,
{
    let mut buf = [0; 1024];
    loop {
        let bytes_read;
        tokio::select! {
            biased;

            result = reader.read(&mut buf) => {
                bytes_read = result?;
            }
            _ = cancel_receiver.recv() => {
                session.cancel_requested();
                break;
            }
        }

        // normal connection close
        if bytes_read == 0 {
            session.connection_closed();
            break;
        }

        writer.write_all(&buf[0..bytes_read]).await?;
        session.bytes_copied(&buf[0..bytes_read]);
    }

    Ok(())
}
