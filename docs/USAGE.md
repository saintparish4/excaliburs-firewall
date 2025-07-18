# Usage Guide

## Prerequisites

- Rust 1.70+ 
- Cargo package manager

## Installation

```bash
git clone https://github.com/your-org/excalibur-firewall.git
cd excalibur-firewall/backend/packet-processor
```

## Running the Packet Processor

### Development Mode
```bash
cargo run
```

### Production Build
```bash
cargo build --release
./target/release/packet-processor
```

## Configuration

The system uses default configurations for:
- Packet processing intervals
- Anomaly detection thresholds
- Signature patterns

## Monitoring

The system outputs:
- **Threat Alerts**: By severity level (Critical, High, Medium, Low)
- **Pattern Statistics**: Every 50 detected patterns
- **Processing Metrics**: Packet counts and rates

## Log Levels

Set log level via environment variable:
```bash
RUST_LOG=debug cargo run
```

Available levels: `error`, `warn`, `info`, `debug`, `trace` 