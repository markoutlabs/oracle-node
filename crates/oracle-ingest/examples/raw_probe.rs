//! Dumps raw frames from one Binance stream URL, for diagnosing decode gaps.
//!
//! ```sh
//! cargo run -p oracle-ingest --example raw_probe -- \
//!   'wss://fstream.binance.com/stream?streams=btcusdt@markPrice@1s' 5
//! ```

use std::time::Duration;

use oracle_ingest::transport::{Connector as _, Transport as _, WebSocketConnector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .ok_or("usage: raw_probe <url> [frames]")?;
    let want: usize = std::env::args()
        .nth(2)
        .and_then(|a| a.parse().ok())
        .unwrap_or(5);

    let mut conn = WebSocketConnector.connect(&url).await?;
    println!("connected to {url}\n");

    if let Some(subscribe) = std::env::args().nth(3) {
        println!("-> {subscribe}");
        conn.send_text(subscribe).await?;
    }

    let mut seen = 0;
    while seen < want {
        match tokio::time::timeout(Duration::from_secs(10), conn.recv()).await {
            Err(_) => {
                println!("(idle 10s)");
                break;
            }
            Ok(Ok(Some(frame))) => match frame.payload() {
                Some(bytes) => {
                    println!("{}", String::from_utf8_lossy(bytes));
                    seen += 1;
                }
                None => println!("(control frame: {frame:?})"),
            },
            Ok(Ok(None)) => {
                println!("(closed by peer)");
                break;
            }
            Ok(Err(err)) => {
                println!("(error: {err})");
                break;
            }
        }
    }
    Ok(())
}
