// src/version/detector.rs
//! Detection of AirPlay device versions.
//! Improved to match Python implementation.

use futures::future::BoxFuture;
use regex::Regex;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Detect version information for an AirPlay device
pub async fn detect_version(
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
    verbose: bool,
) -> Result<Option<HashMap<String, String>>, io::Error> {
    // Try multiple detection methods in order
    let methods = [
        get_info_endpoint,
        get_server_info_airplay2,
        get_airplay_txt_record,
    ];

    for method in methods.iter() {
        match method(ip, port, timeout_duration, verbose).await {
            Ok(Some(info)) if !info.is_empty() => return Ok(Some(info)),
            _ => continue,
        }
    }

    Ok(None)
}

/// Try to get version information from the /info endpoint (AirPlay 1)
fn get_info_endpoint(
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
    verbose: bool,
) -> BoxFuture<'static, Result<Option<HashMap<String, String>>, io::Error>> {
    Box::pin(async move {
        let addr = format!("{}:{}", ip, port);

        if verbose {
            println!("Connecting to {} for /info endpoint", addr);
        }

        let stream_result = timeout(timeout_duration, TcpStream::connect(&addr)).await;

        let mut stream = match stream_result {
            Ok(Ok(stream)) => stream,
            _ => return Ok(None),
        };

        // Send HTTP GET request to the AirPlay info endpoint
        let request = "GET /info HTTP/1.1\r\nHost: localhost\r\nUser-Agent: AirPlay/1.0\r\n\r\n";

        if let Err(_) = stream.write_all(request.as_bytes()).await {
            return Ok(None);
        }

        // Read the response
        let mut buf = vec![0; 8192]; // Larger buffer for bigger responses
        let n = match timeout(timeout_duration, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(None),
        };

        let response = String::from_utf8_lossy(&buf[0..n]).to_string();

        if verbose {
            println!("Response from {}/info: {}", addr, response);
        }

        let mut info = HashMap::new();

        // Parse key-value pairs in the response
        // Patterns to extract from text response
        let key_value_pattern = r#"([a-zA-Z0-9_]+)\s*[=:]\s*"?([^"\r\n]+)"?"#;
        if let Ok(re) = Regex::new(key_value_pattern) {
            for cap in re.captures_iter(&response) {
                if cap.len() >= 3 {
                    let key = cap[1].to_string();
                    let value = cap[2].to_string();
                    info.insert(key, value);
                }
            }
        }

        // Parse plist format (used by some AirPlay devices)
        if response.contains("<plist") || response.contains("<dict>") {
            let plist_pattern = r#"<key>([^<]+)</key>\s*<string>([^<]+)</string>"#;
            if let Ok(re) = Regex::new(plist_pattern) {
                for cap in re.captures_iter(&response) {
                    if cap.len() >= 3 {
                        let key = cap[1].to_string();
                        let value = cap[2].to_string();
                        info.insert(key.to_lowercase(), value);
                    }
                }
            }
        }

        // Parse JSON format (used by some newer devices)
        if response.contains("{") && response.contains("}") {
            // Find JSON content (simple approach)
            if let Some(json_start) = response.find('{') {
                if let Some(json_end) = response[json_start..].rfind('}') {
                    let json_str = &response[json_start..json_start + json_end + 1];

                    // Very simple key-value extraction without a full JSON parser
                    let json_pattern = r#""([^"]+)"\s*:\s*"([^"]+)""#;
                    if let Ok(re) = Regex::new(json_pattern) {
                        for cap in re.captures_iter(json_str) {
                            if cap.len() >= 3 {
                                let key = cap[1].to_string();
                                let value = cap[2].to_string();
                                info.insert(key.to_lowercase(), value);
                            }
                        }
                    }
                }
            }
        }

        Ok(Some(info))
    })
}

/// Try to get version information from AirPlay 2 server-info endpoint
fn get_server_info_airplay2(
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
    verbose: bool,
) -> BoxFuture<'static, Result<Option<HashMap<String, String>>, io::Error>> {
    Box::pin(async move {
        let addr = format!("{}:{}", ip, port);

        if verbose {
            println!("Connecting to {} for /server-info (AirPlay 2)", addr);
        }

        let stream_result = timeout(timeout_duration, TcpStream::connect(&addr)).await;

        let mut stream = match stream_result {
            Ok(Ok(stream)) => stream,
            _ => return Ok(None),
        };

        // Try AirPlay 2 server-info endpoint
        let request =
            "GET /server-info HTTP/1.1\r\nHost: localhost\r\nUser-Agent: AirPlay/2.0\r\n\r\n";

        if let Err(_) = stream.write_all(request.as_bytes()).await {
            return Ok(None);
        }

        // Read the response
        let mut buf = vec![0; 8192];
        let n = match timeout(timeout_duration, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(None),
        };

        let response = String::from_utf8_lossy(&buf[0..n]).to_string();

        if verbose {
            println!("Response from {}/server-info: {}", addr, response);
        }

        let mut info = HashMap::new();

        // Parse plist format (common for AirPlay 2)
        if response.contains("<plist") || response.contains("<dict>") {
            let plist_pattern = r#"<key>([^<]+)</key>\s*<string>([^<]+)</string>"#;
            if let Ok(re) = Regex::new(plist_pattern) {
                for cap in re.captures_iter(&response) {
                    if cap.len() >= 3 {
                        let key = cap[1].to_string();
                        let value = cap[2].to_string();
                        info.insert(key.to_lowercase(), value);
                    }
                }
            }
        }

        // Also look for model and version info in structured data
        let key_patterns = [
            (r#"<key>model</key>\s*<string>([^<]+)</string>"#, "model"),
            (
                r#"<key>deviceid</key>\s*<string>([^<]+)</string>"#,
                "deviceid",
            ),
            (
                r#"<key>features</key>\s*<string>([^<]+)</string>"#,
                "features",
            ),
            (r#"<key>fw</key>\s*<string>([^<]+)</string>"#, "version"),
            (r#"<key>fv</key>\s*<string>([^<]+)</string>"#, "version"),
            (
                r#"<key>srcvers</key>\s*<string>([^<]+)</string>"#,
                "srcvers",
            ),
        ];

        for (pattern, key) in key_patterns.iter() {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(cap) = re.captures(&response) {
                    if cap.len() >= 2 {
                        let value = cap[1].to_string();
                        info.insert(key.to_string(), value);
                    }
                }
            }
        }

        Ok(Some(info))
    })
}

/// Try to get version information from TXT record format
fn get_airplay_txt_record(
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
    verbose: bool,
) -> BoxFuture<'static, Result<Option<HashMap<String, String>>, io::Error>> {
    Box::pin(async move {
        let addr = format!("{}:{}", ip, port);

        if verbose {
            println!("Connecting to {} for TXT record info", addr);
        }

        let stream_result = timeout(timeout_duration, TcpStream::connect(&addr)).await;

        let mut stream = match stream_result {
            Ok(Ok(stream)) => stream,
            _ => return Ok(None),
        };

        // Try a basic HTTP request that might reveal headers with version info
        let request = "OPTIONS * HTTP/1.1\r\nHost: localhost\r\nUser-Agent: AirPlay/310.9\r\n\r\n";

        if let Err(_) = stream.write_all(request.as_bytes()).await {
            return Ok(None);
        }

        // Read the response
        let mut buf = vec![0; 4096];
        let n = match timeout(timeout_duration, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(None),
        };

        let response = String::from_utf8_lossy(&buf[0..n]).to_string();

        if verbose {
            println!("Response from {} OPTIONS: {}", addr, response);
        }

        let mut info = HashMap::new();

        // Look for headers that might contain version info
        let header_patterns = [
            (r#"Server:\s*([^\r\n]+)"#, "server"),
            (r#"AirPlay-Version:\s*([^\r\n]+)"#, "version"),
            (r#"AirTunes-Version:\s*([^\r\n]+)"#, "version"),
            (r#"Apple-TV-Version:\s*([^\r\n]+)"#, "version"),
        ];

        for (pattern, key) in header_patterns.iter() {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(cap) = re.captures(&response) {
                    if cap.len() >= 2 {
                        let value = cap[1].to_string();
                        info.insert(key.to_string(), value);
                    }
                }
            }
        }

        Ok(Some(info))
    })
}
