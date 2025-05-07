# AirPlay Vulnerability Scanner (CVE-2025-24132)

A comprehensive security tool for detecting AirPlay devices potentially vulnerable to the "AirBorne" vulnerability (CVE-2025-24132) and other security issues.

## Project Overview

This project is a hybrid Rust/Python application designed for security researchers and network administrators to identify and assess the security posture of AirPlay-enabled devices on a network. It combines the performance advantages of Rust with Python's rich ecosystem for network discovery and protocol analysis.

## Key Features

- **Multi-Protocol Detection**: Uses mDNS, direct port scanning, and HTTP probing to find AirPlay devices
- **Comprehensive Vulnerability Assessment**: Identifies devices potentially vulnerable to CVE-2025-24132 and other issues
- **Detailed Device Fingerprinting**: Extracts model, version, firmware, and configuration details
- **Cross-Language Integration**: Seamless Rust-Python integration for maximum effectiveness
- **Tailored Security Recommendations**: Device-specific security guidance based on discovered vulnerabilities
- **Rich Output Format**: Color-coded console output with detailed security explanations

## CVE-2025-24132 "AirBorne" Vulnerability

This tool focuses on detecting devices potentially vulnerable to CVE-2025-24132, a critical security flaw in AirPlay implementation affecting a wide range of devices, including:

- Apple devices with outdated firmware
- Smart TVs implementing AirPlay (VIZIO, Samsung, LG, etc.)
- Streaming devices (Roku, Fire TV, etc.)
- Third-party receivers and speakers

The vulnerability can potentially allow:

- Remote code execution
- Information disclosure
- Unauthorized device control
- Network pivoting

## Technical Architecture

### Rust Components

- **Core Scanner**: High-performance port scanning and network enumeration
- **Device Analyzer**: Processing and analysis of discovered devices
- **Python Bridge**: Integration layer connecting Rust and Python components
- **Result Handling**: Structured output generation and vulnerability reporting
- **CLI Interface**: Command-line interface for scanner configuration

### Python Components

- **AirPlay Scanner**: Main discovery tool using multiple detection methods
- **Version Detector**: Advanced version extraction and analysis
- **AirBorne Checker**: Specific tests for CVE-2025-24132 vulnerability
- **AirPlay Simulator**: Proof-of-concept test environment

## Python-Rust Integration

The heart of this project is the `python_bridge.rs` module, which creates a bidirectional bridge between the Rust application and Python scripts. This innovative approach:

1. **Leverages Language Strengths**:

   - Rust for memory safety, performance, and concurrency
   - Python for rapid protocol implementation and network discovery libraries

2. **Maintains Separation of Concerns**:

   - Rust handles the application core, UI, and overall workflow
   - Python handles specialized protocol interactions and discovery

3. **Provides Fallback Mechanisms**:
   - Multiple detection methods ensure maximum device discovery
   - Graceful degradation if some methods fail

### Bridge Implementation

The `python_bridge.rs` file implements several sophisticated techniques:

- Process spawning with appropriate environment configuration
- Structured output parsing from Python scripts
- Conversion of Python-detected devices to Rust data structures
- Detailed error handling and recovery
- Comprehensive logging and diagnostics

## Project Structure

```
airplay-cve/                      # Root directory
├── Cargo.toml                    # Rust project configuration
├── Cargo.lock                    # Rust dependency lock file
├── README.md                     # Project documentation
├── CVE-2025-24132/               # Python scripts directory
│   ├── airplay_scanner.py        # Main Python device scanner
│   ├── airplay_version_detector.py  # Advanced version detection
│   ├── airborne_vuln_checker.py  # CVE-2025-24132 specific tests
│   ├── airplay_simulator.py      # PoC simulator for testing
│   ├── airplay_scan_results/     # Scanner output directory
│   └── airborne_scan/            # Vulnerability scan results
└── src/                          # Rust source code
    ├── main.rs                   # Application entry point
    ├── cli.rs                    # Command-line interface
    ├── python_bridge.rs          # Python integration bridge
    ├── discovery/                # Device discovery modules
    │   ├── mdns.rs               # mDNS discovery implementation
    │   └── mod.rs                # Module definition
    ├── models/                   # Data structures
    │   ├── airplay_device.rs     # AirPlay device model
    │   └── mod.rs                # Module definition
    ├── network/                  # Network utilities
    │   ├── utils.rs              # Network scanning functions
    │   └── mod.rs                # Module definition
    ├── scanner/                  # Scanner implementation
    │   ├── api.rs                # Scanner public API
    │   ├── device_scanner.rs     # Device scanning logic
    │   ├── result_handler.rs     # Result processing
    │   └── mod.rs                # Module definition
    ├── simulator/                # Device simulation
    │   ├── device_simulator.rs   # AirPlay device simulator
    │   └── mod.rs                # Module definition
    └── version/                  # Version analysis
        ├── analyzer.rs           # Version vulnerability analysis
        ├── detector.rs           # Version detection from devices
        └── mod.rs                # Module definition
```

## Technical Details

### Rust Implementation

- **Safe Concurrency**: Uses Tokio for asynchronous operations
- **Cross-Platform Support**: Works on Linux, macOS, and Windows
- **Memory Safety**: Leverages Rust's ownership model to prevent memory-related vulnerabilities
- **Strong Typing**: Comprehensive type system for robust data handling

### Python Implementation

- **mDNS Discovery**: Uses Zeroconf for service discovery
- **Protocol Implementations**: Custom AirPlay protocol implementations
- **Version Fingerprinting**: Advanced version extraction techniques
- **Vulnerability Assessment**: Specialized checks for known vulnerabilities

### Python Bridge

The bridge module implements several key functionalities:

```rust
// Core bridge functionality
pub fn run_python_scanner() -> HashMap<IpAddr, AirPlayDevice> {
    // Configure and spawn Python process with correct environment
    // Process Python stdout for device information
    // Convert Python output to Rust data structures
    // Apply additional analysis and validation
    // Return discovered devices
}
```

## Installation Requirements

### Rust Dependencies

- Rust 1.57 or later
- Cargo package manager
- Required crates:
  - tokio (async runtime)
  - colored (console output)
  - clap (command-line parsing)
  - serde (serialization)

### Python Dependencies

- Python 3.8 or later
- Conda environment management (recommended)
- Required packages:
  - zeroconf (mDNS discovery)
  - requests (HTTP operations)
  - netifaces (network interface discovery)

## Setup Instructions

1. **Clone the repository**:

   ```bash
   git clone https://github.com/cesco345/airplay-cve.git
   cd airplay-cve
   ```

2. **Set up Python environment**:

   ```bash
   Basic environment.
   conda create -n <environment_name>

   Environment with a specific Python version.
   conda create -n myenv python=3.9

   Activate the environment
   conda activate airplay_scanner
   ```

3. **Build the Rust application**:
   ```bash
   cargo build --release
   ```

## Usage

### Basic Scanning

```bash
# Activate Python environment first
conda activate airplay_scanner

# Run with default settings (auto-detects network)
cargo run

# Scan specific network
cargo run -- --network 192.168.1.0/24

# Increase verbosity
cargo run -- --verbose
```

### Advanced Options

```bash
# Export results to JSON
cargo run -- --export results.json

# Specify custom timeout
cargo run -- --timeout 2

# Specify specific ports to scan
cargo run -- --ports 7000,7100,49152,49153
```

### Device Simulation

```bash
# Run the device simulator
cargo run -- --simulate

# Simulate on specific port
cargo run -- --simulate --scan-port 7000
```

## Security Recommendations

The scanner provides comprehensive security recommendations for discovered devices, including:

1. **General AirPlay Security Best Practices**
2. **Device-Specific Mitigations** (Roku, VIZIO, etc.)
3. **Network Protection Strategies**
4. **Advanced Vulnerability Mitigation**
5. **Incident Response Planning**

## Example Output

```
================================================================================
         AirPlay Vulnerability Scanner (Rust Version)
================================================================================

Scanning 192.168.0.0/24 for AirPlay devices...

================================================================================
Detailed Information on Discovered AirPlay Devices:
================================================================================
Device: V435-J01 (CastTV.local.)
IP Address: 192.168.0.162
Version: p20.1.710.30.5-1
Security Status: POTENTIALLY VULNERABLE
Open AirPlay Ports: 7000
Vulnerability Indicators:
  - AirPlay version p20.1.710.30.5-1 is older than 2.7.1

Detailed Device Information:
  model: V435-J01
  manufacturer: VIZIO Inc.
  srcvers: 377.40.00
  ...
================================================================================

COMPREHENSIVE SECURITY RECOMMENDATIONS
================================================================================

General AirPlay Security Recommendations:
1. ✓ Disable AirPlay on devices when not actively in use
2. ✓ Update all AirPlay device firmware to the latest version
...
```

## Why Rust and Python Together?

This project demonstrates the advantages of a polyglot approach to security tooling:

**Rust Provides**:

- Memory safety critical for security tools
- High performance for large network scans
- Strong type system preventing data handling bugs
- Excellent concurrency for parallel scanning
- Compile-time guarantees reducing runtime errors

**Python Enables**:

- Rapid implementation of network protocols
- Easy integration with mDNS libraries
- Simple text processing for version extraction
- Quick prototyping of detection methods
- Dynamic adaptation to different device responses

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues to improve the scanner's capabilities.

## License and Disclaimer

This project is available for educational and security research purposes only. Always obtain proper authorization before scanning any network. This tool should only be used on networks you own or have explicit permission to test.

## Acknowledgments

Special thanks to the security research community for their work on documenting AirPlay vulnerabilities and to the open-source Rust and Python communities for their excellent tools and libraries.
