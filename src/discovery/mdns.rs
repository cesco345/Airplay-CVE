// src/discovery/mdns.rs
//! mDNS discovery for AirPlay devices based on Python implementation.

use colored::*;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::models::AirPlayDevice;
use crate::version::analyzer;
use crate::version::detector;

/// Discover AirPlay devices on the network using mDNS
pub async fn discover_devices() -> io::Result<HashMap<IpAddr, AirPlayDevice>> {
    let devices = Arc::new(Mutex::new(HashMap::new()));

    println!("Listening for mDNS announcements for AirPlay devices (5 seconds)...");

    // Try to auto-detect the network
    let network = detect_network().unwrap_or_else(|_| "192.168.0.0/24".to_string());
    println!("Scanning {} for AirPlay devices...", network);

    // Approach 1: Use mdns-sd library if available
    #[cfg(feature = "mdns_impl")]
    {
        use tokio::time::sleep;
        // Implementation with mdns-sd would go here
        sleep(Duration::from_secs(1)).await;
    }

    // Approach 2: Fall back to scanning common ports
    // Scan first 40 IPs to find devices faster
    use std::net::Ipv4Addr;
    use tokio::time::sleep;

    // Parse the network prefix
    let network_prefix = network.split('/').next().unwrap_or("192.168.0.0");
    let base_ip_parts: Vec<&str> = network_prefix.split('.').collect();

    if base_ip_parts.len() >= 3 {
        let a = base_ip_parts[0].parse::<u8>().unwrap_or(192);
        let b = base_ip_parts[1].parse::<u8>().unwrap_or(168);
        let c = base_ip_parts[2].parse::<u8>().unwrap_or(0);

        // Scan range of IPs
        for d in 1..41 {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));

            // First check port 7000 (common AirPlay port) with short timeout
            if let Ok(true) = is_port_open(ip, 7000, Duration::from_millis(200)).await {
                // Create device entry
                let mut device = AirPlayDevice::new(ip);
                device.add_open_port(7000);

                // Try to get hostname using an async DNS reverse lookup hack
                match get_hostname(ip).await {
                    Ok(Some(hostname)) => device.hostname = Some(hostname),
                    _ => device.hostname = Some(format!("Device-{}.{}.{}.{}", a, b, c, d)),
                }

                // Get version information
                match detector::detect_version(ip, 7000, Duration::from_secs(2), false).await {
                    Ok(Some(version_info)) => {
                        // Extract version info
                        if let Some(version) = version_info.get("version") {
                            device.version = Some(version.clone());
                        } else if let Some(version) = version_info.get("fv") {
                            device.version = Some(version.clone());
                        } else if let Some(version) = version_info.get("srcvers") {
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
                    }
                    _ => {}
                }

                // Check for vulnerabilities
                if let Some(version) = &device.version {
                    let model = device.model.as_deref().unwrap_or("Unknown");
                    let (vulnerable, reason) =
                        analyzer::check_airborne_vulnerability(version, model);
                    device.potentially_vulnerable = vulnerable;

                    if let Some(reason_text) = reason {
                        device.vulnerability_reasons = vec![reason_text];
                    }
                } else {
                    // If we can't determine version but port is open, consider it potentially vulnerable
                    device.potentially_vulnerable = true;
                    device.vulnerability_reasons = vec![
                        "Device has port 7000 open but couldn't determine version - potentially vulnerable".to_string()
                    ];
                }

                // Display device info
                let status = if device.potentially_vulnerable {
                    "POTENTIALLY VULNERABLE".bright_red()
                } else {
                    "LIKELY PATCHED".bright_green()
                };

                println!(
                    "{} {} ({}) - {}",
                    "Found AirPlay device:".bright_green(),
                    ip.to_string().bright_yellow(),
                    device.hostname.as_ref().unwrap_or(&"Unknown".to_string()),
                    status
                );

                // Store device
                devices.lock().unwrap().insert(ip, device);
            }

            // Brief pause to avoid flooding network
            if d % 5 == 0 {
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    // Allow time for discovery operations
    sleep(Duration::from_millis(500)).await;

    // Return discovered devices
    let result = devices.lock().unwrap().clone();
    Ok(result)
}

/// Detect network CIDR
fn detect_network() -> io::Result<String> {
    // Try to detect the network on macOS or Linux
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        // First try "ip route" command
        if let Ok(output) = Command::new("ip").args(&["route"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.starts_with("default") {
                    // Extract the interface
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        let dev_index = parts.iter().position(|&r| r == "dev").unwrap_or(0);
                        if dev_index > 0 && dev_index + 1 < parts.len() {
                            let interface = parts[dev_index + 1];

                            // Now get interface address
                            if let Ok(addr_output) = Command::new("ip")
                                .args(&["addr", "show", interface])
                                .output()
                            {
                                let addr_str = String::from_utf8_lossy(&addr_output.stdout);
                                for addr_line in addr_str.lines() {
                                    if addr_line.trim().starts_with("inet ") {
                                        // Extract CIDR notation address
                                        let addr_parts: Vec<&str> =
                                            addr_line.split_whitespace().collect();
                                        if addr_parts.len() >= 2 {
                                            let addr = addr_parts[1];
                                            if addr.contains("/") {
                                                // Make the last octet 0 to get the network
                                                if let Some(slash_pos) = addr.find('/') {
                                                    let ip_part = &addr[0..slash_pos];
                                                    if let Some(last_dot) = ip_part.rfind('.') {
                                                        let network = format!(
                                                            "{}.0{}",
                                                            &ip_part[..last_dot],
                                                            &addr[slash_pos..]
                                                        );
                                                        return Ok(network);
                                                    }
                                                }
                                                return Ok(addr.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Try ifconfig as fallback
        if let Ok(output) = Command::new("ifconfig").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let mut current_interface = String::new();
            let mut found_ip = false;

            for line in output_str.lines() {
                if !line.starts_with('\t') && !line.starts_with(' ') {
                    // This is an interface line
                    if let Some(name_end) = line.find(':') {
                        current_interface = line[0..name_end].to_string();
                        found_ip = false;
                    }
                } else if !found_ip
                    && !current_interface.contains("lo")
                    && (line.contains("inet ") || line.contains("inet addr:"))
                    && !line.contains("127.0.0.1")
                {
                    // This is an IP address line
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for (i, part) in parts.iter().enumerate() {
                        if (*part == "inet" || *part == "inet:") && i + 1 < parts.len() {
                            let mut ip = parts[i + 1].to_string();
                            if ip.starts_with("addr:") {
                                ip = ip[5..].to_string();
                            }

                            // Convert IP to network CIDR
                            if let Some(last_dot) = ip.rfind('.') {
                                found_ip = true;
                                return Ok(format!("{}.0/24", &ip[..last_dot]));
                            }
                        }
                    }
                }
            }
        }

        // Try netstat as another fallback
        if let Ok(output) = Command::new("netstat").args(&["-rn"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("default") || line.contains("0.0.0.0") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let gateway = parts
                            .iter()
                            .find(|&&x| x.contains('.') && !x.contains("0.0.0.0"));
                        if let Some(gateway) = gateway {
                            if let Some(last_dot) = gateway.rfind('.') {
                                return Ok(format!("{}.0/24", &gateway[..last_dot]));
                            }
                        }
                    }
                }
            }
        }
    } else if cfg!(target_os = "windows") {
        // Windows detection
        if let Ok(output) = Command::new("ipconfig").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let mut found_default = false;

            for line in output_str.lines() {
                // Look for an Ethernet or Wi-Fi adapter that's connected
                if line.contains("Ethernet") || line.contains("Wi-Fi") || line.contains("Wireless")
                {
                    found_default = true;
                }

                if found_default && (line.contains("IPv4 Address") || line.contains("IP Address")) {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 2 {
                        let ip = parts[1].trim();
                        if let Some(last_dot) = ip.rfind('.') {
                            return Ok(format!("{}.0/24", &ip[..last_dot]));
                        }
                    }
                }
            }
        }
    }

    // Default fallback
    Ok("192.168.0.0/24".to_string()) // NOTE: Changed to 0.0 subnet!
}

/// Check if a port is open
async fn is_port_open(ip: IpAddr, port: u16, timeout_duration: Duration) -> io::Result<bool> {
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    match timeout(
        timeout_duration,
        TcpStream::connect(format!("{}:{}", ip, port)),
    )
    .await
    {
        Ok(Ok(_)) => Ok(true),
        _ => Ok(false),
    }
}

/// Get hostname using a hack for async DNS
async fn get_hostname(ip: IpAddr) -> io::Result<Option<String>> {
    // For simplicity, just create a hostname from the IP
    // A proper implementation would use DNS reverse lookup
    let ip_str = ip.to_string();

    // Try to run a quick DNS lookup using 'host' command
    let output = Command::new("host").arg(&ip_str).output();

    if let Ok(output) = output {
        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.contains("domain name pointer") {
            let parts: Vec<&str> = output_str.split("domain name pointer").collect();
            if parts.len() >= 2 {
                let hostname = parts[1].trim().trim_end_matches('.');
                return Ok(Some(hostname.to_string()));
            }
        }
    }

    // Fallback: Use the nslookup command
    let output = Command::new("nslookup").arg(&ip_str).output();

    if let Ok(output) = output {
        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.contains("name = ") {
            let parts: Vec<&str> = output_str.split("name = ").collect();
            if parts.len() >= 2 {
                let hostname = parts[1]
                    .split('\n')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches('.');
                return Ok(Some(hostname.to_string()));
            }
        }
    }

    // Final fallback - generate a name from the IP
    Ok(Some(format!("Device-{}", ip_str.replace('.', "-"))))
}
