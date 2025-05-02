// src/scanner/mod.rs

// Make the modules public
pub mod api;
pub mod device_scanner;
pub mod result_handler;

// Public re-exports
pub use api::run_scan;
pub use device_scanner::DeviceScanner;
pub use result_handler::{export_results, list_discovered_devices, print_security_recommendations};
