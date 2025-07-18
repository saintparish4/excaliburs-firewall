# Excalibur Firewall

A real-time behavioral traffic analysis system built with Rust, Go, and Python.

## Architecture

- **Rust**: Systems programming for high-performance packet processing
- **Go**: Backend development for scalable API services  
- **Python**: Machine learning for behavioral analysis

## Features

- Real-time packet analysis and flow tracking
- Deep packet inspection (DPI) with signature detection
- Behavioral anomaly detection using statistical analysis
- Threat classification with severity levels
- Asynchronous processing pipeline

## Quick Start

```bash
# Build and run the packet processor
cd backend/packet-processor
cargo run
```

## Documentation

See [docs/](docs/) for detailed usage and deployment guides.

## Security

Please review our [Security Policy](SECURITY.md) before reporting vulnerabilities.

## License

MIT/Apache 2.0 - see [LICENSE](LICENSE) for details.

## RUST ENGINE DIAGRAM
Raw Packet → DPI Engine → Patterns
     ↓
Raw Packet → Flow Tracker → Patterns + Timing Anomalies
     ↓
All Patterns → Pattern-to-Threat Conversion → Threat Indicators
     ↓
Threats → Threat Monitoring Loop (logs by severity)
Patterns → Pattern Monitoring Loop (statistics)