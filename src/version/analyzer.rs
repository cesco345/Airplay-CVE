// src/version/analyzer.rs
//! Analysis of AirPlay version information to determine vulnerability status.

use std::cmp::Ordering;
use std::collections::HashMap;

/// Compare version strings
/// Returns Ordering::Less if version1 < version2, etc.
pub fn compare_versions(version1: &str, version2: &str) -> Ordering {
    let v1_parts: Vec<u32> = version1
        .split('.')
        .map(|s| s.parse::<u32>().unwrap_or(0))
        .collect();

    let v2_parts: Vec<u32> = version2
        .split('.')
        .map(|s| s.parse::<u32>().unwrap_or(0))
        .collect();

    let max_len = v1_parts.len().max(v2_parts.len());

    for i in 0..max_len {
        let v1_part = if i < v1_parts.len() { v1_parts[i] } else { 0 };
        let v2_part = if i < v2_parts.len() { v2_parts[i] } else { 0 };

        match v1_part.cmp(&v2_part) {
            Ordering::Equal => continue,
            other => return other,
        }
    }

    Ordering::Equal
}

/// Check if a device with the given version and model is potentially vulnerable
/// to the AirPlay Airborne vulnerability or other known issues.
///
/// Returns (is_vulnerable, reason)
pub fn check_airborne_vulnerability(version: &str, model: &str) -> (bool, Option<String>) {
    // AirPlay Airborne vulnerability - affects many versions below 2.7.1
    let min_safe_version = "2.7.1";

    // Check older versions potentially vulnerable
    if compare_versions(version, min_safe_version) == Ordering::Less {
        return (
            true,
            Some(format!(
                "AirPlay version {} is older than {}",
                version, min_safe_version
            )),
        );
    }

    // Check model-specific vulnerabilities
    match model.to_lowercase().as_str() {
        m if m.contains("homepod") && compare_versions(version, "3.0.0") == Ordering::Less => {
            return (
                true,
                Some(format!(
                    "HomePod devices with version {} may be susceptible to audio command injection",
                    version
                )),
            );
        }
        m if m.contains("appletv") && compare_versions(version, "2.9.0") == Ordering::Less => {
            return (
                true,
                Some(format!(
                    "AppleTV with version {} may be vulnerable to network request forgery",
                    version
                )),
            );
        }
        _ => {}
    }

    // No known vulnerabilities
    (false, None)
}

/// Get a list of vulnerable version thresholds by device type
pub fn get_vulnerable_thresholds() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "All",
            "2.7.1",
            "AirPlay Airborne vulnerability affects all devices with versions below 2.7.1",
        ),
        (
            "HomePod",
            "3.0.0",
            "HomePod-specific audio command injection vulnerability",
        ),
        (
            "AppleTV",
            "2.9.0",
            "AppleTV-specific network request forgery vulnerability",
        ),
    ]
}

/// Map device info strings to standardized model names
pub fn normalize_model_name(device_info: &HashMap<String, String>) -> Option<String> {
    // Look for model information in different fields
    for key in &["model", "am", "deviceid", "features"] {
        if let Some(value) = device_info.get(*key) {
            let value = value.to_lowercase();

            // Match known patterns
            if value.contains("appletv") {
                return Some("AppleTV".to_string());
            } else if value.contains("homepod") {
                return Some("HomePod".to_string());
            } else if value.contains("macbook") || value.contains("imac") || value.contains("mac") {
                return Some("Mac".to_string());
            } else if value.contains("iphone") {
                return Some("iPhone".to_string());
            } else if value.contains("ipad") {
                return Some("iPad".to_string());
            }
        }
    }

    None
}
