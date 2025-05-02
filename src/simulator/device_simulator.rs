// src/simulator/device_simulator.rs
// Simplified to work with the new CLI implementation

use colored::*;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

// Run the device simulator
pub async fn run_simulator(
    port: u16,
    verbose: bool,
    _vulnerable: bool, // Changed to use underscore to avoid unused variable warning
) -> io::Result<()> {
    // Print banner
    println!("\n{}", "=".repeat(80).bright_purple().bold());
    println!(
        "{}",
        "         AirPlay Device Simulator".bright_purple().bold()
    );
    println!("{}", "=".repeat(80).bright_purple().bold());

    println!("Starting AirPlay device simulator on port {}...", port);

    // Setup TCP listener for incoming connections
    let address = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&address).await?;

    println!("AirPlay device simulator listening on port {}", port);
    println!("Press Ctrl+C to stop the simulator");

    // Channel for handling shutdown
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

    // Handle Ctrl+C
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            let _ = shutdown_tx_clone.send(()).await;
        }
    });

    // Main server loop
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((mut socket, addr)) => {
                        println!("Connection from {}", addr);

                        // Spawn a task to handle this connection
                        tokio::spawn(async move {
                            let mut buf = vec![0; 1024];

                            match socket.read(&mut buf).await {
                                Ok(n) => {
                                    if n == 0 {
                                        return; // Connection closed
                                    }

                                    let request = String::from_utf8_lossy(&buf[..n]);
                                    if verbose {
                                        println!("Received request: {}", request);
                                    }

                                    // Simple HTTP response for /info endpoint
                                    if request.starts_with("GET /info") {
                                        let response = concat!(
                                            "HTTP/1.1 200 OK\r\n",
                                            "Content-Type: text/plain\r\n",
                                            "\r\n",
                                            "deviceid=AA:BB:CC:DD:EE:FF\r\n",
                                            "features=0x5A7FFFF7,0x1E\r\n",
                                            "model=AppleTV5,3\r\n",
                                            "srcvers=220.68\r\n",
                                            "vv=2\r\n",
                                            "protovers=1.0\r\n",
                                            "pi=b08f5a79-db29-4384-b456-a4784d9e6055\r\n",
                                            "pk=8b48928c07695d9c46e8e5d1c0979936cc48938610f5ee0397787384b2e54c2c\r\n",
                                            "version=2.5.0\r\n"
                                        );

                                        if let Err(e) = socket.write_all(response.as_bytes()).await {
                                            eprintln!("Error writing response: {}", e);
                                        }
                                    } else {
                                        // Default response for other requests
                                        let response = "HTTP/1.1 404 Not Found\r\n\r\n";
                                        if let Err(e) = socket.write_all(response.as_bytes()).await {
                                            eprintln!("Error writing response: {}", e);
                                        }
                                    }
                                },
                                Err(e) => {
                                    eprintln!("Error reading from socket: {}", e);
                                }
                            }
                        });
                    },
                    Err(e) => {
                        eprintln!("Error accepting connection: {}", e);
                    }
                }
            },
            _ = shutdown_rx.recv() => {
                println!("Shutting down simulator...");
                break;
            }
        }
    }

    Ok(())
}
