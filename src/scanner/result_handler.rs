// src/scanner/result_handler.rs
// This is a simplified version focusing on compatibility with the new CLI implementation

use colored::*;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::Path;

use crate::models::AirPlayDevice;

// Enum for output format (simplified)
pub enum OutputFormat {
    Json,
    Text,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Json
    }
}

// List discovered devices
pub fn list_discovered_devices(devices: &HashMap<IpAddr, AirPlayDevice>) {
    println!("\n{}\n", "=".repeat(80).bright_blue());
    println!("{}", "Discovered AirPlay Devices:".bright_green());

    if devices.is_empty() {
        println!("No AirPlay devices found.");
        return;
    }

    for (ip, device) in devices {
        let status = if device.potentially_vulnerable {
            "POTENTIALLY VULNERABLE".bright_red()
        } else {
            "LIKELY PATCHED".bright_green()
        };

        println!("\n{} ({})", ip.to_string().bright_yellow(), status);

        if let Some(hostname) = &device.hostname {
            println!("  - Hostname: {}", hostname);
        }

        if let Some(model) = &device.model {
            println!("  - Model: {}", model);
        }

        if let Some(version) = &device.version {
            println!("  - Version: {}", version);
        }

        if !device.open_ports.is_empty() {
            println!("  - Open Ports: {:?}", device.open_ports);
        }

        if !device.vulnerability_reasons.is_empty() {
            println!("  - Vulnerability Reasons:");
            for reason in &device.vulnerability_reasons {
                println!("    * {}", reason);
            }
        }
    }

    println!("\n{}\n", "=".repeat(80).bright_blue());
}

// Print security recommendations
pub fn print_security_recommendations() {
    println!("\n{}", "Security Recommendations:".bright_green());
    println!("  - Update all AirPlay devices to the latest firmware");
    println!("  - Isolate IoT devices on a separate network segment");
    println!("  - Consider disabling AirPlay if not needed");
    println!("  - Monitor network traffic for unusual AirPlay activity");
}

// Export results to file
pub fn export_results(devices: &HashMap<IpAddr, AirPlayDevice>, path: &str) -> io::Result<()> {
    // Get current timestamp
    let now = chrono::Local::now();
    let timestamp = now.format("%Y-%m-%d_%H-%M-%S").to_string();

    // Create filename if not provided
    let filename = if path.is_empty() {
        format!("airplay_scan_{}.json", timestamp)
    } else {
        path.to_string()
    };

    // Prepare data for export
    let mut export_data = Vec::new();

    for (ip, device) in devices {
        let export_device = serde_json::json!({
            "ip": ip.to_string(),
            "hostname": device.hostname,
            "model": device.model,
            "version": device.version,
            "open_ports": device.open_ports,
            "version_info": device.version_info,
            "potentially_vulnerable": device.potentially_vulnerable,
            "vulnerability_reasons": device.vulnerability_reasons,
            "scan_timestamp": timestamp,
        });

        export_data.push(export_device);
    }

    // Write to file
    let json_data = serde_json::to_string_pretty(&export_data)?;
    fs::write(&filename, json_data)?;

    Ok(())
}
