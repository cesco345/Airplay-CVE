// src/python_bridge.rs
// Enhanced bridge with updated path to Python scripts - complete version

use crate::models::AirPlayDevice;
use colored::*;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

pub fn run_python_scanner() -> HashMap<IpAddr, AirPlayDevice> {
    let mut devices = HashMap::new();

    println!(
        "{}",
        "Running Python AirPlay scanner via bridge...".bright_blue()
    );
    println!("This will use your existing Python tools to find devices\n");

    // Updated path to the Python scripts in the same directory
    let correct_path = "./CVE-2025-24132/airplay_scanner.py";

    println!("Using Python script at: {}", correct_path);

    // Run with the conda environment's Python
    let output = Command::new("/opt/anaconda3/envs/airplay_scanner/bin/python")
        .arg(correct_path)
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                println!("Python scanner completed successfully");

                // Parse the output and create devices with enhanced information
                parse_python_output_enhanced(&stdout, &mut devices);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("Conda Python scanner failed: {}", stderr);

                // Try with system Python as fallback
                let sys_output = Command::new("python").arg(correct_path).output();

                if let Ok(sys_output) = sys_output {
                    if sys_output.status.success() {
                        let stdout = String::from_utf8_lossy(&sys_output.stdout);
                        println!("System Python scanner completed successfully");
                        parse_python_output_enhanced(&stdout, &mut devices);
                    } else {
                        println!("System Python scanner also failed");
                    }
                }
            }
        }
        Err(e) => {
            println!("Failed to execute Python scanner: {}", e);
        }
    }

    // If no devices found with Python scanner, try the version detector
    if devices.is_empty() {
        println!("\nTrying Python AirPlay version detector as fallback...");

        // Updated path to the version detector script
        let version_detector_path = "./CVE-2025-24132/airplay_version_detector.py";

        let detector_output = Command::new("/opt/anaconda3/envs/airplay_scanner/bin/python")
            .arg(version_detector_path)
            .output();

        if let Ok(output) = detector_output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                println!("Version detector completed successfully");
                parse_python_output_enhanced(&stdout, &mut devices);
            }
        }
    }

    // If still no devices found, try the airborne vulnerability checker
    if devices.is_empty() {
        println!("\nTrying airborne vulnerability checker as a final fallback...");

        let airborne_checker_path = "./CVE-2025-24132/airborne_vuln_checker.py";

        let airborne_output = Command::new("/opt/anaconda3/envs/airplay_scanner/bin/python")
            .arg(airborne_checker_path)
            .output();

        if let Ok(output) = airborne_output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                println!("Airborne vulnerability checker completed successfully");
                parse_python_output_enhanced(&stdout, &mut devices);
            }
        }
    }

    // If we found devices, display detailed information
    if !devices.is_empty() {
        println!("\n{}", "=".repeat(80).bright_blue());
        println!(
            "{}",
            "Detailed Information on Discovered AirPlay Devices:".bright_yellow()
        );
        println!("{}\n", "=".repeat(80).bright_blue());

        for (ip, device) in &devices {
            let status = if device.potentially_vulnerable {
                "POTENTIALLY VULNERABLE".bright_red()
            } else {
                "LIKELY PATCHED".bright_green()
            };

            println!("{}", "=".repeat(80).bright_blue());
            println!(
                "{} {} ({})",
                "Device:".bright_green(),
                device
                    .model
                    .as_ref()
                    .unwrap_or(&"Unknown".to_string())
                    .bright_yellow(),
                device
                    .hostname
                    .as_ref()
                    .unwrap_or(&"Unknown".to_string())
                    .bright_cyan()
            );
            println!(
                "{} {}",
                "IP Address:".bright_green(),
                ip.to_string().bright_yellow()
            );

            if let Some(version) = &device.version {
                println!("{} {}", "Version:".bright_green(), version.bright_yellow());
            }

            println!("{} {}", "Security Status:".bright_green(), status);

            // Fixed the formatting of port numbers
            println!(
                "{} {}",
                "Open AirPlay Ports:".bright_green(),
                device
                    .open_ports
                    .iter()
                    .map(|&p| p.to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
                    .bright_yellow()
            );

            if !device.vulnerability_reasons.is_empty() {
                println!("{}", "Vulnerability Indicators:".bright_green());
                for reason in &device.vulnerability_reasons {
                    println!("  - {}", reason.bright_red());
                }
            }

            // Display all version info found by the Python scanner
            if !device.version_info.is_empty() {
                println!("\n{}", "Detailed Device Information:".bright_green());
                for (key, value) in &device.version_info {
                    println!("  {}: {}", key.bright_cyan(), value);
                }
            }

            println!("{}", "=".repeat(80).bright_blue());
        }

        // Display device-specific recommendations
        display_device_specific_recommendations(&devices);
    } else {
        println!("No devices found via Python scanner.");
    }

    // Always return the devices, even if empty
    devices
}

// Display tailored security recommendations based on discovered devices
fn display_device_specific_recommendations(devices: &HashMap<IpAddr, AirPlayDevice>) {
    // Count vulnerable devices by type
    let mut vulnerable_roku = false;
    let mut vulnerable_vizio = false;
    let mut vulnerable_other = false;

    for (_ip, device) in devices {
        if !device.potentially_vulnerable {
            continue;
        }

        if let Some(model) = &device.model {
            let model_lower = model.to_lowercase();
            if model_lower.contains("roku") || model_lower.contains("3810x") {
                vulnerable_roku = true;
            } else if model_lower.contains("vizio") || model_lower.contains("v435") {
                vulnerable_vizio = true;
            } else {
                vulnerable_other = true;
            }
        }
    }

    // Display comprehensive security recommendations
    println!("\n{}", "=".repeat(80).bright_red());
    println!(
        "{}",
        "COMPREHENSIVE SECURITY RECOMMENDATIONS".bright_red().bold()
    );
    println!("{}", "=".repeat(80).bright_red());

    println!(
        "\n{}",
        "General AirPlay Security Recommendations:"
            .bright_yellow()
            .bold()
    );
    println!(
        "1. {} Disable AirPlay on devices when not actively in use",
        "✓".bright_green()
    );
    println!(
        "2. {} Update all AirPlay device firmware to the latest version",
        "✓".bright_green()
    );
    println!(
        "3. {} Create a separate IoT network/VLAN for smart devices",
        "✓".bright_green()
    );
    println!(
        "4. {} Enable AirPlay password protection where available",
        "✓".bright_green()
    );
    println!(
        "5. {} Monitor network traffic for unusual AirPlay activity",
        "✓".bright_green()
    );
    println!(
        "6. {} Use a firewall to restrict AirPlay traffic to known devices only",
        "✓".bright_green()
    );

    // Device-specific recommendations
    if vulnerable_roku {
        println!(
            "\n{}",
            "Roku Device Recommendations:".bright_yellow().bold()
        );
        println!(
            "1. {} Update Roku firmware via Settings > System > System Update",
            "✓".bright_green()
        );
        println!(
            "2. {} Disable AirPlay when not in use: Settings > Apple AirPlay & HomeKit > Off",
            "✓".bright_green()
        );
        println!(
            "3. {} Enable 'Require device verification' in AirPlay settings",
            "✓".bright_green()
        );
        println!(
            "4. {} Set a strong AirPlay code/password in AirPlay settings",
            "✓".bright_green()
        );
    }

    if vulnerable_vizio {
        println!("\n{}", "VIZIO TV Recommendations:".bright_yellow().bold());
        println!(
            "1. {} Update VIZIO firmware: Menu > System > Check for Updates",
            "✓".bright_green()
        );
        println!("2. {} Disable AirPlay when not in use: Menu > SmartCast Home > Extras > Apple AirPlay > Off", "✓".bright_green());
        println!(
            "3. {} Enable 'Require Code' for first-time AirPlay connections",
            "✓".bright_green()
        );
        println!(
            "4. {} Apply device filtering by enabling 'Require Device Verification'",
            "✓".bright_green()
        );
    }

    // Network protection recommendations
    println!(
        "\n{}",
        "Network Protection Recommendations:".bright_yellow().bold()
    );
    println!(
        "1. {} Configure your router/firewall to block external access to port 7000",
        "✓".bright_green()
    );
    println!(
        "2. {} Segment your network - isolate IoT devices from your main network",
        "✓".bright_green()
    );
    println!(
        "3. {} Consider using a dedicated IoT security gateway/appliance",
        "✓".bright_green()
    );
    println!(
        "4. {} Install and configure intrusion detection systems to monitor for AirPlay exploits",
        "✓".bright_green()
    );
    println!(
        "5. {} Regularly scan your network for vulnerable devices",
        "✓".bright_green()
    );

    // Advanced recommendations
    println!(
        "\n{}",
        "Advanced Protection Measures:".bright_yellow().bold()
    );
    println!(
        "1. {} Create firewall rules to restrict AirPlay traffic to known MAC addresses",
        "✓".bright_green()
    );
    println!(
        "2. {} Consider network level packet inspection for AirPlay traffic anomalies",
        "✓".bright_green()
    );
    println!(
        "3. {} Use VLANs to isolate AirPlay devices from sensitive network segments",
        "✓".bright_green()
    );
    println!(
        "4. {} Implement scheduled network access controls to disable AirPlay during non-use hours",
        "✓".bright_green()
    );
    println!("5. {} Consider replacing vulnerable devices if manufacturer no longer provides security updates", "✓".bright_green());

    // Exploit mitigation recommendations
    println!(
        "\n{}",
        "Specific Vulnerability Mitigation:".bright_yellow().bold()
    );
    println!("1. {} Protect against AirBorne vulnerability (CVE-2025-24132) by disabling AirPlay or updating firmware", "✓".bright_green());
    println!(
        "2. {} Monitor for unusual outbound traffic from AirPlay devices",
        "✓".bright_green()
    );
    println!(
        "3. {} Implement deep packet inspection to detect AirPlay exploit patterns",
        "✓".bright_green()
    );
    println!(
        "4. {} Consider implementing MAC address whitelisting for AirPlay connections",
        "✓".bright_green()
    );
    println!(
        "5. {} Use a DNS sinkhole to block known malicious domains that exploit AirPlay",
        "✓".bright_green()
    );

    // Incident response recommendations
    println!("\n{}", "Incident Response Planning:".bright_yellow().bold());
    println!(
        "1. {} Document all AirPlay devices on your network with firmware versions",
        "✓".bright_green()
    );
    println!(
        "2. {} Establish a protocol for responding to security incidents involving IoT devices",
        "✓".bright_green()
    );
    println!("3. {} Create a backup plan for essential services if AirPlay devices must be taken offline", "✓".bright_green());
    println!(
        "4. {} Maintain offline backups of IoT device configurations",
        "✓".bright_green()
    );
    println!(
        "5. {} Develop a reporting process for identified vulnerabilities",
        "✓".bright_green()
    );

    // Testing recommendations
    println!(
        "\n{}",
        "Security Testing Recommendations:".bright_yellow().bold()
    );
    println!(
        "1. {} Periodically scan your network for unauthorized AirPlay devices",
        "✓".bright_green()
    );
    println!(
        "2. {} Test AirPlay device configurations for unintended accessibility",
        "✓".bright_green()
    );
    println!(
        "3. {} Verify network segmentation effectiveness regularly",
        "✓".bright_green()
    );
    println!(
        "4. {} Conduct simulated attacks against your AirPlay infrastructure",
        "✓".bright_green()
    );
    println!(
        "5. {} Validate firewall rules controlling AirPlay traffic",
        "✓".bright_green()
    );

    println!("\nFor comprehensive details on securing your AirPlay devices:");
    println!("- Visit device manufacturers' security pages for specific guidance");
    println!("- Consult network security best practices for IoT device protection");
    println!("- Consider professional security assessment for high-security environments");

    println!(
        "\n{}",
        "DISCLAIMER: This scan was performed for educational and security research purposes only."
            .bright_red()
    );
    println!("{}", "=".repeat(80).bright_red());

    // Additional documentation reference
    println!("\n{}", "Additional Resources:".bright_yellow().bold());
    println!("1. Apple AirPlay Security Documentation: https://support.apple.com/guide/security/airplay-security-sec03c0337c/web");
    println!("2. NIST Guide to IoT Security: https://www.nist.gov/publications/considerations-managing-internet-things-iot-cybersecurity-and-privacy-risks");
    println!("3. Consumer Reports Smart TV Security Guidelines");
    println!("4. Router-specific IoT security guides from major manufacturers");
    println!("5. CVE-2025-24132 Technical Details and Mitigation Strategies");
}

// Enhanced parsing function to extract more information
fn parse_python_output_enhanced(output: &str, devices: &mut HashMap<IpAddr, AirPlayDevice>) {
    // Track current device being parsed
    let mut current_ip: Option<IpAddr> = None;
    let mut device_info_block = false;
    let mut device_info_content = String::new();
    let mut vulnerability_section = false;

    // Process the output line by line
    for line in output.lines() {
        // Check for IP address patterns to identify device sections
        if line.contains("IP Address:") {
            let ip_parts: Vec<&str> = line.split("IP Address:").collect();
            if ip_parts.len() >= 2 {
                let ip_str = ip_parts[1].trim();
                if let Ok(ip) = IpAddr::from_str(ip_str) {
                    // Store the current IP being processed
                    current_ip = Some(ip);

                    // Create a new device if it doesn't exist
                    if !devices.contains_key(&ip) {
                        let device = AirPlayDevice::new(ip);
                        devices.insert(ip, device);
                    }
                }
            }
        }
        // Parse hostname if found
        else if line.contains("Hostname:") && current_ip.is_some() {
            let hostname_parts: Vec<&str> = line.split("Hostname:").collect();
            if hostname_parts.len() >= 2 {
                let hostname = hostname_parts[1].trim().to_string();
                if let Some(ip) = current_ip {
                    if let Some(device) = devices.get_mut(&ip) {
                        device.hostname = Some(hostname);
                    }
                }
            }
        }
        // Parse port information
        else if line.contains("Open AirPlay Ports:") && current_ip.is_some() {
            let port_parts: Vec<&str> = line.split("Open AirPlay Ports:").collect();
            if port_parts.len() >= 2 {
                let port_str = port_parts[1].trim();
                for port in port_str.split(',') {
                    if let Ok(port_num) = port.trim().parse::<u16>() {
                        if let Some(ip) = current_ip {
                            if let Some(device) = devices.get_mut(&ip) {
                                device.add_open_port(port_num);
                            }
                        }
                    }
                }
            }
        }
        // Parse vulnerability status
        else if line.contains("Security Status:") && current_ip.is_some() {
            if line.contains("VULNERABLE") {
                if let Some(ip) = current_ip {
                    if let Some(device) = devices.get_mut(&ip) {
                        device.potentially_vulnerable = true;
                    }
                }
            }
        }
        // Parse risk level
        else if line.contains("Risk Level:") && current_ip.is_some() {
            let risk_parts: Vec<&str> = line.split("Risk Level:").collect();
            if risk_parts.len() >= 2 {
                let risk_level = risk_parts[1].trim().to_string();
                if let Some(ip) = current_ip {
                    if let Some(device) = devices.get_mut(&ip) {
                        if risk_level.contains("HIGH") {
                            device.potentially_vulnerable = true;
                            if !device
                                .vulnerability_reasons
                                .contains(&"High risk device".to_string())
                            {
                                device
                                    .vulnerability_reasons
                                    .push("High risk device".to_string());
                            }
                        }
                    }
                }
            }
        }
        // Parse model information
        else if (line.contains("Model:") || line.contains("Device:")) && current_ip.is_some() {
            let parts: Vec<&str> = if line.contains("Model:") {
                line.split("Model:").collect()
            } else {
                line.split("Device:").collect()
            };

            if parts.len() >= 2 {
                let model = parts[1].trim().to_string();
                if let Some(ip) = current_ip {
                    if let Some(device) = devices.get_mut(&ip) {
                        device.model = Some(model);
                    }
                }
            }
        }
        // Parse version information
        else if line.contains("Version:") && current_ip.is_some() {
            let version_parts: Vec<&str> = line.split("Version:").collect();
            if version_parts.len() >= 2 {
                let version = version_parts[1].trim().to_string();
                if let Some(ip) = current_ip {
                    if let Some(device) = devices.get_mut(&ip) {
                        device.version = Some(version);
                    }
                }
            }
        }
        // Check for Vulnerability Indicators section start
        else if line.contains("Vulnerability Indicators:") && current_ip.is_some() {
            vulnerability_section = true;
        }
        // Parse vulnerability indicators/reasons
        else if (vulnerability_section || line.contains("Indicators:"))
            && line.trim().starts_with("-")
            && current_ip.is_some()
        {
            let reason = line.trim().trim_start_matches('-').trim().to_string();
            if !reason.is_empty() {
                if let Some(ip) = current_ip {
                    if let Some(device) = devices.get_mut(&ip) {
                        if !device.vulnerability_reasons.contains(&reason) {
                            device.vulnerability_reasons.push(reason);
                        }
                    }
                }
            }
        }
        // Check for Device Info block start
        else if line.contains("Device Info:") && current_ip.is_some() {
            device_info_block = true;
            device_info_content.clear();
        }
        // Process Device Info content
        else if device_info_block && current_ip.is_some() {
            // Check if we're exiting the device info block
            if line.trim() == "}" {
                device_info_block = false;

                // Parse device info content
                parse_device_info(&device_info_content, current_ip, devices);
            } else {
                // Add to device info content
                device_info_content.push_str(line);
                device_info_content.push('\n');
            }
        }
        // Check for Detection Method
        else if line.contains("Detection Method:") && current_ip.is_some() {
            let method_parts: Vec<&str> = line.split("Detection Method:").collect();
            if method_parts.len() >= 2 {
                let method = method_parts[1].trim().to_string();
                if let Some(ip) = current_ip {
                    if let Some(device) = devices.get_mut(&ip) {
                        device
                            .version_info
                            .insert("detection_method".to_string(), method);
                    }
                }
            }
        }
        // Check for device section end (separator line)
        else if line.contains("----------") {
            current_ip = None;
            device_info_block = false;
            vulnerability_section = false;
        }
    }

    // Add default vulnerability reason if none specified
    for (_ip, device) in devices.iter_mut() {
        if device.potentially_vulnerable && device.vulnerability_reasons.is_empty() {
            device
                .vulnerability_reasons
                .push("Initial detection, vulnerability status unknown".to_string());
        }
    }
}

// Parse device info JSON-like content
fn parse_device_info(
    content: &str,
    ip_opt: Option<IpAddr>,
    devices: &mut HashMap<IpAddr, AirPlayDevice>,
) {
    let ip = match ip_opt {
        Some(ip) => ip,
        None => return,
    };

    let device = match devices.get_mut(&ip) {
        Some(device) => device,
        None => return,
    };

    // Extract key-value pairs from the content
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line == "{" || line == "}" {
            continue;
        }

        // Split on colon or equals
        let parts: Vec<&str> = line.splitn(2, |c| c == ':' || c == '=').collect();
        if parts.len() < 2 {
            continue;
        }

        let mut key = parts[0].trim().trim_matches('"').trim_matches('\'');
        let mut value = parts[1]
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .trim_matches(',');

        // Clean up quotation marks from JSON-like format
        if key.starts_with("\"") && key.ends_with("\"") {
            key = &key[1..key.len() - 1];
        }
        if value.starts_with("\"") && value.ends_with("\"") {
            value = &value[1..value.len() - 1];
        }

        // Store in version_info map
        if !key.is_empty() && !value.is_empty() {
            // Clean up trailing quotes in value
            let clean_value = value.trim_end_matches('"').to_string();
            device.version_info.insert(key.to_string(), clean_value);

            // Also check for specific keys we're interested in
            match key {
                "model" => {
                    if device.model.is_none() {
                        device.model = Some(value.trim_end_matches('"').to_string());
                    }
                }
                "fv" | "srcvers" | "version" => {
                    if device.version.is_none() {
                        device.version = Some(value.trim_end_matches('"').to_string());
                    }
                }
                _ => {}
            }

            // Check for vulnerability indicators in the device info
            if key.to_lowercase().contains("vulnerable") && value.to_lowercase().contains("true") {
                device.potentially_vulnerable = true;

                if !device
                    .vulnerability_reasons
                    .contains(&format!("{} flag is set to true", key))
                {
                    device
                        .vulnerability_reasons
                        .push(format!("{} flag is set to true", key));
                }
            }
        }
    }
}
