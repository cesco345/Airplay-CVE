// src/main.rs

use colored::*;
use std::time::Duration;

mod cli;
mod discovery;
mod models;
mod network;
mod python_bridge;
mod scanner;
mod simulator;
mod version;

fn main() {
    // Parse command-line arguments
    let args = cli::parse_args();

    // Print banner
    print_banner();

    // Create a runtime
    let rt = tokio::runtime::Runtime::new().unwrap();

    if args.simulate {
        // Run device simulator
        println!("Starting AirPlay device simulator...");
        let result = rt.block_on(async {
            simulator::device_simulator::run_simulator(args.scan_port, args.verbose, false).await
        });

        if let Err(e) = result {
            eprintln!("Error running simulator: {}", e);
        }
    } else {
        // Run scanner
        println!("Starting AirPlay vulnerability scanner...");
        let result = rt.block_on(async {
            scanner::api::run_scan(
                args.network.clone(),
                args.ports.clone(),
                Duration::from_secs(args.timeout),
                args.export.clone(),
                args.verbose,
            )
            .await
        });

        // Standard scanner ran - now try Python bridge
        println!("\n{}", "=".repeat(80).bright_blue());
        println!(
            "{}",
            "Trying Python bridge for better device discovery...".bright_yellow()
        );
        println!("{}\n", "=".repeat(80).bright_blue());

        // Run the Python bridge scanner
        let python_devices = python_bridge::run_python_scanner();

        if python_devices.is_empty() {
            println!("\nNo additional devices found via Python bridge.");
        } else {
            println!(
                "\nSuccessfully found {} devices using Python bridge!",
                python_devices.len()
            );

            // If export was requested, pass the Python-found devices to the exporter
            if let Some(export_path) = &args.export {
                let _ = scanner::result_handler::export_results(&python_devices, export_path);
                println!("Results exported to: {}", export_path.bright_green());
            }
        }

        if let Err(e) = result {
            eprintln!("Note: Standard scanner had error: {}", e);
        }
    }
}

fn print_banner() {
    println!("\n{}", "=".repeat(80).bright_purple().bold());
    println!(
        "{}",
        "         AirPlay Vulnerability Scanner (Rust Version)"
            .bright_purple()
            .bold()
    );
    println!("{}\n", "=".repeat(80).bright_purple().bold());
}
