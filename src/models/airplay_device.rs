// src/models/airplay_device.rs
//! AirPlay device data structure.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Represents an AirPlay device with its properties and vulnerability status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirPlayDevice {
    /// IP address of the device
    pub ip: Option<IpAddr>,

    /// Hostname or mDNS name of the device
    pub hostname: Option<String>,

    /// Model name of the device
    pub model: Option<String>,

    /// Version of the AirPlay software/firmware
    pub version: Option<String>,

    /// Open ports that respond to AirPlay protocol
    pub open_ports: Vec<u16>,

    /// Whether the device is potentially vulnerable to CVE-2025-24132
    pub potentially_vulnerable: bool,

    /// Reasons why the device is considered vulnerable
    pub vulnerability_reasons: Vec<String>,

    /// Methods used to detect this device
    pub detection_methods: Vec<String>,

    /// All version-related information collected
    #[serde(serialize_with = "serialize_hashmap")]
    pub version_info: HashMap<String, String>,
}

impl AirPlayDevice {
    /// Create a new minimal AirPlay device entry
    pub fn new(ip: IpAddr) -> Self {
        AirPlayDevice {
            ip: Some(ip),
            hostname: None,
            model: None,
            version: None,
            open_ports: Vec::new(),
            potentially_vulnerable: true,
            vulnerability_reasons: vec![
                "Initial detection, vulnerability status unknown".to_string(),
            ],
            detection_methods: Vec::new(),
            version_info: HashMap::new(),
        }
    }

    /// Create an AirPlay device entry from mDNS discovery
    pub fn from_mdns(ip: IpAddr, hostname: String, port: u16) -> Self {
        AirPlayDevice {
            ip: Some(ip),
            hostname: Some(hostname),
            model: None,
            version: None,
            open_ports: vec![port],
            potentially_vulnerable: true,
            vulnerability_reasons: vec!["Initial detection via mDNS".to_string()],
            detection_methods: vec!["mDNS".to_string()],
            version_info: HashMap::new(),
        }
    }

    /// Update the device with port scan results
    pub fn add_open_port(&mut self, port: u16) {
        if !self.open_ports.contains(&port) {
            self.open_ports.push(port);
        }

        if !self.detection_methods.contains(&"port_scan".to_string()) {
            self.detection_methods.push("port_scan".to_string());
        }
    }

    /// Add version information and update vulnerability status
    pub fn update_version_info(
        &mut self,
        version_info: HashMap<String, String>,
        detection_method: &str,
    ) {
        // Add the detection method
        if !self
            .detection_methods
            .contains(&detection_method.to_string())
        {
            self.detection_methods.push(detection_method.to_string());
        }

        // Update model if available
        if let Some(model) = version_info.get("model") {
            self.model = Some(model.clone());
        }

        // Update version if available
        for key in &[
            "version",
            "srcvers",
            "protovers",
            "fw_version",
            "server_version",
        ] {
            if let Some(version) = version_info.get(*key) {
                self.version = Some(version.clone());
                break;
            }
        }

        // Add all version info
        for (key, value) in version_info {
            self.version_info.insert(key, value);
        }
    }
}

// Custom serializer for HashMap that ensures it gets serialized correctly in JSON
fn serialize_hashmap<S>(map: &HashMap<String, String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    let mut map_serializer = serializer.serialize_map(Some(map.len()))?;
    for (k, v) in map {
        map_serializer.serialize_entry(k, v)?;
    }
    map_serializer.end()
}
