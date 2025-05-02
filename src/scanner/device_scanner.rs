// src/scanner/device_scanner.rs
//! Scanner for AirPlay devices on the network.

use colored::*;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Import network utilities
use crate::models::AirPlayDevice;
use crate::network::utils;
use crate::version::detector;

// Define AirPlay ports (moved from utils.rs)
const AIRPLAY_PORTS: [u16; 2] = [7000, 7100];

/// Scanner for AirPlay devices
pub struct DeviceScanner {
    timeout: Duration,
    verbose: bool,
}

impl DeviceScanner {
    /// Create a new scanner
    pub fn new(timeout: Duration, verbose: bool) -> Self {
        Self { timeout, verbose }
    }

    /// Scan a single IP for AirPlay devices
    pub async fn scan_ip(
        &self,
        ip: IpAddr,
        devices: Arc<Mutex<HashMap<IpAddr, AirPlayDevice>>>,
    ) -> io::Result<()> {
        if self.verbose {
            println!(
                "{} {}",
                "Scanning".bright_blue(),
                ip.to_string().bright_yellow()
            );
        }

        // Scan for open AirPlay ports
        let mut open_ports = Vec::new();

        // Check each common AirPlay port
        for &port in &AIRPLAY_PORTS {
            // Use the is_port_open function from utils
            if utils::is_port_open(ip, port, self.timeout).await? {
                open_ports.push(port);
            }
        }

        // If any ports are open, create/update device
        if !open_ports.is_empty() {
            println!(
                "{} {}",
                "Found AirPlay ports on".bright_blue(),
                ip.to_string().bright_yellow(),
            );

            // Try to get hostname
            let hostname = utils::get_hostname(ip).await?.map(|h| h.to_string());

            // Create initial device
            let mut device = AirPlayDevice::new(ip);
            device.hostname = hostname;

            // Add open ports
            for port in open_ports.iter() {
                device.add_open_port(*port);
            }

            // Try to detect version
            if let Some(port) = open_ports.first() {
                if let Some(version_info) =
                    detector::detect_version(ip, *port, self.timeout, self.verbose).await?
                {
                    // Extract version
                    if let Some(version) = version_info.get("version") {
                        device.version = Some(version.clone());
                    }

                    // Extract model
                    if let Some(model) = version_info.get("model") {
                        device.model = Some(model.clone());
                    }

                    // Add all version info
                    for (key, value) in version_info {
                        device.version_info.insert(key, value);
                    }

                    // Check if potentially vulnerable
                    self.check_vulnerabilities(&mut device);
                }
            }

            // Store the device
            let mut devices_lock = devices.lock().unwrap();
            devices_lock.insert(ip, device);
        } else if self.verbose {
            println!("No AirPlay ports found on {}", ip);
        }

        Ok(())
    }

    /// Check for known vulnerabilities based on version
    fn check_vulnerabilities(&self, device: &mut AirPlayDevice) {
        if let Some(version) = &device.version {
            // Check for Airborne vulnerability (AirPlay versions below 2.7.1)
            // Use the compare_versions function from analyzer instead of is_version_vulnerable
            if crate::version::analyzer::compare_versions(version, "2.7.1")
                == std::cmp::Ordering::Less
            {
                device.potentially_vulnerable = true;
                device
                    .vulnerability_reasons
                    .push(format!("AirPlay version {} is older than 2.7.1", version));
            }

            // Check for device-specific vulnerabilities
            if let Some(model) = &device.model {
                // HomePod specific check
                if model.to_lowercase().contains("homepod")
                    && crate::version::analyzer::compare_versions(version, "3.0.0")
                        == std::cmp::Ordering::Less
                {
                    device.potentially_vulnerable = true;
                    device.vulnerability_reasons.push(format!(
                        "HomePod devices with version {} may be susceptible to audio command injection",
                        version
                    ));
                }

                // AppleTV specific check
                if model.to_lowercase().contains("appletv")
                    && crate::version::analyzer::compare_versions(version, "2.9.0")
                        == std::cmp::Ordering::Less
                {
                    device.potentially_vulnerable = true;
                    device.vulnerability_reasons.push(format!(
                        "AppleTV with version {} may be vulnerable to network request forgery",
                        version
                    ));
                }
            }
        }
    }

    /// Scan a network CIDR range for AirPlay devices
    pub async fn scan_network(
        &self,
        cidr: &str,
        devices: Arc<Mutex<HashMap<IpAddr, AirPlayDevice>>>,
    ) -> io::Result<()> {
        // Parse IP addresses from CIDR
        let ips = utils::parse_cidr(cidr)?;

        println!("Scanning {} hosts for AirPlay services", ips.len());
        println!("Scanning {} hosts in parallel...", ips.len());

        // Create tasks for each IP
        use futures::stream::{self, StreamExt};

        // Process IPs in parallel with a limit
        const PARALLEL_SCANS: usize = 100;
        let mut tasks = stream::iter(ips)
            .map(|ip| {
                let devices_clone = devices.clone();
                let scanner = self.clone();
                async move {
                    if let Err(e) = scanner.scan_ip(ip, devices_clone).await {
                        if scanner.verbose {
                            println!("Error scanning {}: {}", ip, e);
                        }
                    }
                }
            })
            .buffer_unordered(PARALLEL_SCANS);

        // Wait for all tasks to complete
        while let Some(_) = tasks.next().await {}

        Ok(())
    }
}

// Implement Clone for DeviceScanner (needed for async tasks)
impl Clone for DeviceScanner {
    fn clone(&self) -> Self {
        Self {
            timeout: self.timeout,
            verbose: self.verbose,
        }
    }
}
