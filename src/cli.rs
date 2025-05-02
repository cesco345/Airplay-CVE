// This is a simplified fix for the command-line interface
// Replace or update your src/cli.rs file with this

use clap::{Arg, Command};

pub struct CliArgs {
    pub network: Option<String>,
    pub timeout: u64,
    pub ports: Vec<u16>,
    pub export: Option<String>,
    pub scan_port: u16,
    pub simulate: bool,
    pub verbose: bool,
}

pub fn parse_args() -> CliArgs {
    let matches = Command::new("AirPlay Vulnerability Scanner")
        .version("0.1.0")
        .about("Scans for potentially vulnerable AirPlay devices on the network")
        .arg(
            Arg::new("network")
                .short('n')
                .long("network")
                .value_name("CIDR")
                .help("Network CIDR to scan (e.g., 192.168.1.0/24)")
                .required(false),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .value_name("SECONDS")
                .help("Connection timeout in seconds")
                .default_value("2")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("ports")
                .short('p')
                .long("ports")
                .value_name("PORT,PORT,...")
                .help("Comma-separated list of ports to scan")
                .default_value("7000,7100")
                .value_delimiter(','),
        )
        .arg(
            Arg::new("export")
                .short('e')
                .long("export")
                .value_name("FILENAME")
                .help("Export results to JSON file"),
        )
        .arg(
            Arg::new("scan_port")
                .long("scan-port")
                .value_name("PORT")
                .help("Port to use for device simulator")
                .default_value("7000")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("simulate")
                .short('s')
                .long("simulate")
                .help("Run device simulator instead of scanner")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    // Parse ports
    let ports: Vec<u16> = matches
        .get_many::<String>("ports")
        .unwrap_or_default()
        .map(|s| s.parse::<u16>().unwrap_or(7000))
        .collect();

    CliArgs {
        network: matches.get_one::<String>("network").cloned(),
        timeout: *matches.get_one::<u64>("timeout").unwrap_or(&2),
        ports,
        export: matches.get_one::<String>("export").cloned(),
        scan_port: *matches.get_one::<u16>("scan_port").unwrap_or(&7000),
        simulate: matches.get_flag("simulate"),
        verbose: matches.get_flag("verbose"),
    }
}
