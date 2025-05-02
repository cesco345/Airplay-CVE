
// src/network/utils.rs
//! Network utility functions for scanning and analyzing network devices.

use colored::*;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use ipnetwork::IpNetwork;
use std::str::FromStr;
use std::process::Command;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::net::TcpStream;
use tokio::time::timeout;
use crate::models::AirPlayDevice;

// Define common AirPlay ports
pub const AIRPLAY_PORTS: [u16; 4] = [7000, 7100, 49152, 49153];

/// Check if a port is open on a given IP address
pub async fn is_port_open(ip: IpAddr, port: u16, timeout_duration: Duration) -> io::Result<bool> {
    let addr = SocketAddr::new(ip, port);
    
    match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(_)) => Ok(false),
        Err(_) => Ok(false), // Timeout is treated as closed port
    }
}

/// Get hostname for an IP address if possible
pub async fn get_hostname(ip: IpAddr) -> io::Result<Option<String>> {
    let ip_str = ip.to_string();
    
    // Try to run a quick DNS lookup using 'host' command
    let output = Command::new("host")
        .arg(&ip_str)
        .output();
        
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
    let output = Command::new("nslookup")
        .arg(&ip_str)
        .output();
        
    if let Ok(output) = output {
        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.contains("name = ") {
            let parts: Vec<&str> = output_str.split("name = ").collect();
            if parts.len() >= 2 {
                let hostname = parts[1].split('\n').next().unwrap_or("").trim().trim_end_matches('.');
                return Ok(Some(hostname.to_string()));
            }
        }
    }
    
    // Final fallback - generate a name from the IP
    Ok(Some(format!("Device-{}", ip_str.replace('.', "-"))))
}

/// Parse CIDR notation into a list of IP addresses
pub fn parse_cidr(cidr: &str) -> io::Result<Vec<IpAddr>> {
    match IpNetwork::from_str(cidr) {
        Ok(network) => {
            match network {
                IpNetwork::V4(ipv4_network) => {
                    let addresses: Vec<IpAddr> = ipv4_network.iter().map(|ip| IpAddr::V4(ip)).collect();
                    Ok(addresses)
                },
                IpNetwork::V6(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv6 networks are not supported for scanning",
                )),
            }
        },
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string())),
    }
}

/// Detect current network
pub fn get_local_network() -> io::Result<String> {
    // First try for macOS and Linux
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        // Use ip route command first
        if let Ok(output) = Command::new("ip")
            .args(&["route", "show", "default"])
            .output() 
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("default") {
                    // Extract the interface
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(dev_idx) = parts.iter().position(|&r| r == "dev") {
                        if dev_idx + 1 < parts.len() {
                            let interface = parts[dev_idx + 1];
                            
                            // Now get interface address
                            if let Ok(addr_output) = Command::new("ip")
                                .args(&["addr", "show", interface])
                                .output() 
                            {
                                let addr_str = String::from_utf8_lossy(&addr_output.stdout);
                                for line in addr_str.lines() {
                                    if line.contains("inet ") && !line.contains("127.0.0.1") {
                                        // Extract CIDR
                                        let parts: Vec<&str> = line.split_whitespace().collect();
                                        for part in parts {
                                            if part.contains("/") {
                                                // Try to convert to network by setting last octet to 0
                                                if let Some(slash_idx) = part.find('/') {
                                                    let ip_part = &part[..slash_idx];
                                                    if let Some(last_dot) = ip_part.rfind('.') {
                                                        return Ok(format!("{}.0{}", &ip_part[..last_dot], &part[slash_idx..]));
                                                    } else {
                                                        return Ok(part.to_string());
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
            }
        }
        
        // Try ifconfig as fallback
        if let Ok(output) = Command::new("ifconfig")
            .output() 
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let mut current_interface = String::new();
            
            for line in output_str.lines() {
                if !line.starts_with('\t') && !line.starts_with(' ') {
                    // This is an interface line
                    if line.contains(": ") {
                        current_interface = line.split(": ").next().unwrap_or("").to_string();
                    }
                } else if !current_interface.contains("lo") && 
                          (line.contains("inet ") || line.contains("inet addr:")) && 
                          !line.contains("127.0.0.1") {
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
                                return Ok(format!("{}.0/24", &ip[..last_dot]));
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Windows-specific network detection
    if cfg!(target_os = "windows") {
        if let Ok(output) = Command::new("ipconfig")
            .output() 
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let mut found_adapter = false;
            
            for line in output_str.lines() {
                if line.contains("Ethernet") || line.contains("Wi-Fi") || 
                   line.contains("Wireless") || line.contains("Wireless LAN") {
                    found_adapter = true;
                }
                
                if found_adapter && (line.contains("IPv4 Address") || line.contains("IP Address")) {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 2 {
                        let ip = parts[1].trim();
                        if let Some(last_dot) = ip.rfind('.') {
                            return Ok(format!("{}.0/24", &ip[..last_dot]));
                        }
                    }
                    
                    found_adapter = false; // Reset for next adapter
                }
            }
        }
    }
    
    // macOS-specific network detection 
    if cfg!(target_os = "macos") {
        // Try to get default route interface
        if let Ok(output) = Command::new("route")
            .args(&["-n", "get", "default"])
            .output() 
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let mut interface = String::new();
            
            for line in output_str.lines() {
                if line.contains("interface:") {
                    interface = line.split(':').nth(1).unwrap_or("").trim().to_string();
                    break;
                }
            }
            
            if !interface.is_empty() {
                // Now get IP address for this interface
                if let Ok(ifconfig_output) = Command::new("ifconfig")
                    .arg(&interface)
                    .output() 
                {
                    let ifconfig_str = String::from_utf8_lossy(&ifconfig_output.stdout);
                    for line in ifconfig_str.lines() {
                        if line.contains("inet ") && !line.contains("127.0.0.1") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 2 {
                                let ip = parts[1];
                                if let Some(last_dot) = ip.rfind('.') {
                                    return Ok(format!("{}.0/24", &ip[..last_dot]));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Ultimate fallback - try multiple common subnets
    for subnet in &["192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/24", "10.0.1.0/24"] {
        return Ok(subnet.to_string());
    }
    
    Ok("192.168.0.0/24".to_string()) // Final default
}

/// Scan a range of ports on a single IP
pub async fn scan_ports(
    ip: IpAddr, 
    ports: &[u16], 
    timeout_duration: Duration
) -> io::Result<Vec<u16>> {
    let mut open_ports = Vec::new();
    
    for &port in ports {
        if is_port_open(ip, port, timeout_duration).await? {
            open_ports.push(port);
            
            println!(
                "{} {} - Port {}",
                "Found device with open AirPlay ports:".bright_green(),
                ip.to_string().bright_yellow(),
                port
            );
        }
    }
    
    Ok(open_ports)
}

/// Scan common AirPlay ports
pub async fn scan_airplay_ports(
    ip: IpAddr, 
    timeout_duration: Duration
) -> io::Result<Vec<u16>> {
    scan_ports(ip, &AIRPLAY_PORTS, timeout_duration).await
}

/// Scan a network range for AirPlay devices
pub async fn scan_network_parallel(
    ips: Vec<IpAddr>,
    timeout_duration: Duration,
    devices: Arc<Mutex<HashMap<IpAddr, AirPlayDevice>>>,
) -> io::Result<()> {
    use futures::stream::{self, StreamExt};
    use crate::version::detector;
    use crate::version::analyzer;
    
    println!("Scanning {} hosts in parallel...", ips.len());
    
    // Process up to 100 IPs in parallel
    let mut tasks = stream::iter(ips)
        .map(|ip| {
            let devices_clone = devices.clone();
            let timeout = timeout_duration;
            
            async move {
                // Check common AirPlay ports
                let mut open_ports = Vec::new();
                for &port in &AIRPLAY_PORTS {
                    if is_port_open(ip, port, timeout).await.unwrap_or(false) {
                        open_ports.push(port);
                    }
                }
                
                if !open_ports.is_empty() {
                    println!("Scanning {}", ip);
                    
                    // Create device
                    let mut device = AirPlayDevice::new(ip);
                    
                    // Add open ports
                    for port in &open_ports {
                        device.add_open_port(*port);
                    }
                    
                    // Try to get hostname
                    if let Ok(Some(hostname)) = get_hostname(ip).await {
                        device.hostname = Some(hostname);
                    }
                    
                    // Try to detect version on the first open port
                    if let Some(&port) = open_ports.first() {
                        if let Ok(Some(version_info)) = detector::detect_version(ip, port, timeout, false).await {
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
                    }
                    
                    // Check for vulnerabilities
                    if let Some(version) = &device.version {
                        let model = device.model.as_deref().unwrap_or("Unknown");
                        let (vulnerable, reason) = analyzer::check_airborne_vulnerability(version, model);
                        device.potentially_vulnerable = vulnerable;
                        
                        if let Some(reason_text) = reason {
                            device.vulnerability_reasons = vec![reason_text];
                        }
                    } else {
                        // If port is open but can't determine version, consider it potentially vulnerable
                        device.potentially_vulnerable = true;
                        device.vulnerability_reasons = vec![
                            "Device has AirPlay ports open but couldn't determine version - potentially vulnerable".to_string()
                        ];
                    }
                    
                    // Store device in shared map
                    let mut devices_lock = devices_clone.lock().unwrap();
                    devices_lock.insert(ip, device);
                } else {
                    // No AirPlay ports open
                }
            }
        })
        .buffer_unordered(100);
    
    // Wait for all tasks to complete
    while let Some(_) = tasks.next().await {}
    
    Ok(())
}