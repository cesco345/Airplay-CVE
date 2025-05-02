// src/scanner/api.rs
// Fix ports parameter and other compatibility issues

use colored::*;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::discovery;
use crate::models::AirPlayDevice;
use crate::scanner::device_scanner::DeviceScanner;
use crate::scanner::result_handler;

// Function to run the scanning process
pub async fn run_scan(
    network: Option<String>,
    _ports: Vec<u16>, // Add underscore to indicate intentionally unused
    timeout: Duration,
    export_path: Option<String>,
    verbose: bool,
) -> io::Result<()> {
    println!(
        "{}",
        "Looking for AirPlay devices with mDNS...".bright_blue()
    );

    // Discover devices via mDNS
    let discovered_devices = discovery::mdns::discover_devices().await?;

    // Create shared devices map for scanner
    let devices_arc = Arc::new(Mutex::new(discovered_devices.clone()));

    // If network range specified, scan it
    if let Some(network_cidr) = network {
        // Scan the specified network range
        let local_network = network_cidr.clone();

        println!(
            "{} {}",
            "Scanning local network".bright_blue(),
            local_network.bright_yellow()
        );

        // Create scanner with correct parameters (timeout, verbose)
        let scanner = DeviceScanner::new(timeout, verbose);

        // Call scan_network with both network_cidr and devices_arc
        scanner
            .scan_network(&network_cidr, devices_arc.clone())
            .await?;
    }

    // Get the final devices map
    let final_devices = devices_arc.lock().unwrap().clone();

    // List discovered devices
    result_handler::list_discovered_devices(&final_devices);

    // Print security recommendations
    result_handler::print_security_recommendations();

    println!(
        "{}",
        "This check was performed for educational and security purposes only.".bright_yellow()
    );

    // Export results if requested
    if let Some(path) = export_path {
        println!(
            "{} {}{}",
            "Results saved to: ".bright_yellow(),
            path.bright_green(),
            "".bright_yellow()
        );
        result_handler::export_results(&final_devices, &path)?;
    }

    Ok(())
}
