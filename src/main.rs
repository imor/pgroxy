use futures::FutureExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

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

            let (client_copied, upstream_copied) = tokio::join! {
                copy_bytes(&mut client_reader, &mut upstream_writer, "client", "upstream", cancel_sender.subscribe())
                    .then(|r| { let _ = cancel_sender.send(()); async { r } }),
                copy_bytes(&mut upstream_reader, &mut client_writer, "upstream", "client", cancel_sender.subscribe())
                    .then(|r| { let _ = cancel_sender.send(()); async { r } }),
            };

            match client_copied {
                Ok(count) => {
                    eprintln!("Copied total {count} bytes from client to upstream in this session")
                }
                Err(e) => eprintln!("Failed to copy bytes from client to upstream; err = {e:?}"),
            }
            match upstream_copied {
                Ok(count) => {
                    eprintln!("Copied total {count} bytes from upstream to client in this session")
                }
                Err(e) => eprintln!("Failed to copy bytes from upstream to client; err = {e:?}"),
            }
        });
    }
}

async fn copy_bytes<R, W>(
    reader: &mut R,
    writer: &mut W,
    source_name: &str,
    dest_name: &str,
    mut cancel_receiver: broadcast::Receiver<()>,
) -> tokio::io::Result<usize>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut bytes_copied = 0;
    let mut buf = [0; 1024];
    loop {
        let bytes_read;
        tokio::select! {
            biased;

            result = reader.read(&mut buf) => {
                bytes_read = result?;
            }
            _ = cancel_receiver.recv() => {
                eprintln!("Closing connection to {source_name}");
                break;
            }
        }

        // normal connection close
        if bytes_read == 0 {
            eprintln!("Connection from {source_name} closed");
            break;
        }

        writer.write_all(&buf[0..bytes_read]).await?;
        eprintln!("Copied {bytes_read} bytes from {source_name} to {dest_name}");
        bytes_copied += bytes_read;
    }

    Ok(bytes_copied)
}
