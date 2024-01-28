use bytes::BytesMut;
use decoder::{ClientMessageDecoder, ServerMessageDecoder};
use futures::FutureExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_util::codec::Decoder;

use crate::decoder::create_decoders;
mod decoder;

trait HalfSession {
    fn bytes_copied(&mut self, bytes: &[u8]);
    fn connection_closed(&self);
    fn cancel_requested(&self);
}

struct ClientToUpstreamSession {
    buf: BytesMut,
    decoder: ClientMessageDecoder,
    total_bytes_copied: u64,
}

impl HalfSession for ClientToUpstreamSession {
    fn bytes_copied(&mut self, bytes: &[u8]) {
        self.total_bytes_copied += bytes.len() as u64;
        eprintln!("Copied {} bytes from client to upstream", bytes.len());

        self.buf.extend_from_slice(bytes);
        let message = self.decoder.decode(&mut self.buf);
        match message {
            Ok(Some(msg)) => {
                eprintln!("Decoded msg: {msg:?}")
            }
            Ok(None) => eprintln!("not enough data to decode message"),
            Err(e) => eprintln!("error decoding message: {e:?}"),
        }
    }

    fn connection_closed(&self) {
        eprintln!("Client closed the connection");
    }

    fn cancel_requested(&self) {
        eprintln!("Closing connection from client");
    }
}

struct UpstreamToClientSession {
    buf: BytesMut,
    decoder: ServerMessageDecoder,
    total_bytes_copied: u64,
}

impl HalfSession for UpstreamToClientSession {
    fn bytes_copied(&mut self, bytes: &[u8]) {
        self.total_bytes_copied += bytes.len() as u64;
        eprintln!("Copied {} bytes from upstream to client", bytes.len());

        self.buf.extend_from_slice(bytes);
        let message = self.decoder.decode(&mut self.buf);
        match message {
            Ok(Some(msg)) => eprintln!("Decoded msg: {msg:?}"),
            Ok(None) => eprintln!("not enough data to decode message"),
            Err(e) => eprintln!("error decoding message: {e:?}"),
        }
    }

    fn connection_closed(&self) {
        eprintln!("Upstream closed the connection");
    }

    fn cancel_requested(&self) {
        eprintln!("Closing connection to upstream");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:8080";
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on {addr}");

    loop {
        let (mut client, client_addr) = listener.accept().await?;
        println!("Received a client connection from {client_addr}");

        tokio::spawn(async move {
            let upstream_addr = "127.0.0.1:5431";
            let mut upstream = match TcpStream::connect(upstream_addr).await {
                Ok(upstream) => upstream,
                Err(e) => {
                    eprintln!("failed to connect to upstream; err = {e:?}");
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
            };
            let mut upstream_to_client_session = UpstreamToClientSession {
                buf: BytesMut::new(),
                decoder: server_msg_decoder,
                total_bytes_copied: 0,
            };

            let (client_res, upstream_res) = tokio::join! {
                copy_bytes(&mut client_reader, &mut upstream_writer,
                        &mut client_to_upstream_session, cancel_sender.subscribe())
                    .then(|r| { let _ = cancel_sender.send(()); async { r } }),
                copy_bytes(&mut upstream_reader, &mut client_writer,
                        &mut upstream_to_client_session, cancel_sender.subscribe())
                    .then(|r| { let _ = cancel_sender.send(()); async { r } }),
            };

            eprintln!(
                "Copied total {} bytes from client to upstream in this session",
                client_to_upstream_session.total_bytes_copied
            );
            eprintln!(
                "Copied total {} bytes from upstream to client in this session",
                upstream_to_client_session.total_bytes_copied
            );
            if let Err(e) = client_res {
                eprintln!("Error while copying bytes from client to upstream; err = {e:?}");
            }
            if let Err(e) = upstream_res {
                eprintln!("Error while copying bytes from upstream to client; err = {e:?}");
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
