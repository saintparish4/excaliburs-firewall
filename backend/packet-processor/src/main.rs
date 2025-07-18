use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Custom error types for better error handling
#[derive(Error, Debug)]
pub enum PacketProcessorError {
    #[error("Invalid packet data: {0}")]
    InvalidPacketData(String),
    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

// Core packet structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPacket {
    pub timestamp: u64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub payload: Vec<u8>,
    pub packet_size: usize,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowMetrics {
    pub first_seen: u64,
    pub last_seen: u64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub average_packet_size: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralPattern {
    pub pattern_id: String,
    pub pattern_type: PatternType,
    pub confidence: f32,
    pub detection_time: u64,
    pub flow_key: FlowKey,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PatternType {
    PortScan,
    DdosAttack,
    DataExfiltration,
    BotnetCommunication,
    AnomalousTraffic,
    Malware,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub severity: ThreatLevel,
    pub indicator_type: String,
    pub description: String,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub timestamp: u64,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)] 
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

// Deep Packet Inspection Engine
pub struct DpiEngine {
    signatures: HashMap<String, Vec<u8>>,
    http_analyzer: HttpAnalyzer,
    dns_analyzer: DnsAnalyzer,
}

impl DpiEngine {
    pub fn new() -> Self {
        let mut engine = DpiEngine {
            signatures: HashMap::new(),
            http_analyzer: HttpAnalyzer::new(),
            dns_analyzer: DnsAnalyzer::new(),
        };

        engine.load_signatures();
        engine
    }

    fn load_signatures(&mut self) {
        // HTTP Signatures
        self.signatures
            .insert("HTTP_GET".to_string(), b"GET".to_vec());
        self.signatures
            .insert("HTTP_POST".to_string(), b"POST".to_vec());

        // Malware signatures (simplified examples)
        self.signatures
            .insert("MALWARE_BEACON".to_string(), b"BEACON".to_vec());

        // Suspicious patterns
        self.signatures
            .insert("SQL_INJECTION".to_string(), b"SELECT * FROM".to_vec());
        self.signatures
            .insert("XSS_ATTEMPT".to_string(), b"<script>".to_vec());
    }

    pub fn inspect_packet(&self, packet: &RawPacket) -> Result<Vec<BehavioralPattern>> {
        let mut patterns = Vec::new();

        // Signature-based detection
        for (sig_name, signature) in &self.signatures {
            if self.contains_signature(&packet.payload, signature) {
                patterns.push(BehavioralPattern {
                    pattern_id: format!("SIG_{}", sig_name),
                    pattern_type: self.signature_to_pattern_type(sig_name),
                    confidence: 0.8,
                    detection_time: packet.timestamp,
                    flow_key: self.extract_flow_key(packet),
                    metadata: HashMap::new(),
                });
            }
        }

        // Protocol-specific analysis
        match packet.protocol {
            6 => patterns.extend(self.http_analyzer.analyze(packet)?), //TCP
            17 => patterns.extend(self.dns_analyzer.analyze(packet)?), //UDP
            _ => {}
        }

        Ok(patterns)
    }

    fn contains_signature(&self, payload: &[u8], signature: &[u8]) -> bool {
        payload
            .windows(signature.len())
            .any(|window| window == signature)
    }

    fn signature_to_pattern_type(&self, sig_name: &str) -> PatternType {
        match sig_name {
            s if s.contains("MALWARE") => PatternType::Malware,
            s if s.contains("BEACON") => PatternType::BotnetCommunication,
            s if s.contains("SQL") || s.contains("XSS") => PatternType::AnomalousTraffic,
            _ => PatternType::AnomalousTraffic,
        }
    }

    fn extract_flow_key(&self, packet: &RawPacket) -> FlowKey {
        FlowKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
        }
    }
}

// HTTP Protocol Analyzer
pub struct HttpAnalyzer;

impl HttpAnalyzer {
    pub fn new() -> Self {
        HttpAnalyzer
    }

    pub fn analyze(&self, packet: &RawPacket) -> Result<Vec<BehavioralPattern>> {
        let mut patterns = Vec::new();

        if packet.dst_port != 80 && packet.dst_port != 443 {
            return Ok(patterns);
        }

        let payload_str = String::from_utf8_lossy(&packet.payload);

        // Check for suspicious HTTP Patterns
        if payload_str.contains("User-Agent: bot") || payload_str.contains("User-Agent: crawler") {
            patterns.push(BehavioralPattern {
                pattern_id: "HTTP_BOT_UA".to_string(),
                pattern_type: PatternType::BotnetCommunication,
                confidence: 0.7,
                detection_time: packet.timestamp,
                flow_key: FlowKey {
                    src_ip: packet.src_ip,
                    dst_ip: packet.dst_ip,
                    src_port: packet.src_port,
                    dst_port: packet.dst_port,
                    protocol: packet.protocol,
                },
                metadata: [("user_agent".to_string(), "suspicious".to_string())].into(),
            });
        }

        // Check for data exfiltration
        if payload_str.contains("POST") && packet.payload.len() > 10240 {
            patterns.push(BehavioralPattern {
                pattern_id: "HTTP_LARGE_POST".to_string(),
                pattern_type: PatternType::DataExfiltration,
                confidence: 0.8,
                detection_time: packet.timestamp,
                flow_key: FlowKey {
                    src_ip: packet.src_ip,
                    dst_ip: packet.dst_ip,
                    src_port: packet.src_port,
                    dst_port: packet.dst_port,
                    protocol: packet.protocol,
                },
                metadata: [("size".to_string(), packet.payload.len().to_string())].into(),
            });
        }

        Ok(patterns)
    }
}

// DNS Protocol Analyzer
pub struct DnsAnalyzer {
    baseline_metrics: Arc<Mutex<HashMap<FlowKey, Vec<f64>>>>,
    window_size: usize,
    anomaly_threshold: f64,
}

impl DnsAnalyzer {
    pub fn new() -> Self {
        DnsAnalyzer {
            baseline_metrics: Arc::new(Mutex::new(HashMap::new())),
            window_size: 100,
            anomaly_threshold: 2.0,
        }
    }

    pub fn analyze(&self, packet: &RawPacket) -> Result<Vec<BehavioralPattern>> {
        let mut patterns = Vec::new();

        if packet.dst_port != 53 {
            return Ok(patterns);
        }

        let flow_key = FlowKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
        };

        // Check for DNS tunneling (abnormally large queries)
        if packet.payload.len() > 512 {
            patterns.push(BehavioralPattern {
                pattern_id: "DNS_LARGE_QUERY".to_string(),
                pattern_type: PatternType::DataExfiltration,
                confidence: 0.6,
                detection_time: packet.timestamp,
                flow_key: flow_key.clone(),
                metadata: [("query_size".to_string(), packet.payload.len().to_string())].into(),
            });
        }

        // Check for packet size anomalies
        if let Ok(Some(anomaly)) = self.detect_packet_size_anomaly(&flow_key, packet.packet_size as f64) {
            patterns.push(anomaly);
        }

        Ok(patterns)
    }

    fn detect_packet_size_anomaly(
        &self,
        flow_key: &FlowKey,
        packet_size: f64,
    ) -> Result<Option<BehavioralPattern>> {
        let mut metrics = self.baseline_metrics.lock().unwrap();
        let sizes = metrics.entry(flow_key.clone()).or_insert_with(Vec::new);

        // Add current packet size
        sizes.push(packet_size);

        // Maintain window size
        if sizes.len() > self.window_size {
            sizes.remove(0);
        }

        // Need sufficient data for analysis
        if sizes.len() < 20 {
            return Ok(None);
        }

        // Calculate statistics
        let mean = sizes.iter().sum::<f64>() / sizes.len() as f64;
        let variance = sizes.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / sizes.len() as f64;
        let std_dev = variance.sqrt();

        // Check for anomaly
        if std_dev > 0.0 && (packet_size - mean).abs() > self.anomaly_threshold * std_dev {
            let mut metadata = HashMap::new();
            metadata.insert("packet_size".to_string(), packet_size.to_string());
            metadata.insert("mean_size".to_string(), mean.to_string());
            metadata.insert("std_dev".to_string(), std_dev.to_string());
            metadata.insert(
                "z_score".to_string(),
                ((packet_size - mean) / std_dev).to_string(),
            );

            return Ok(Some(BehavioralPattern {
                pattern_id: "PACKET_SIZE_ANOMALY".to_string(),
                pattern_type: PatternType::AnomalousTraffic,
                confidence: 0.7,
                detection_time: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_micros() as u64,
                flow_key: flow_key.clone(),
                metadata,
            }));
        }
        Ok(None)
    }
}

// Flow tracking and behavioral analysis
pub struct FlowTracker {
    flows: Arc<Mutex<HashMap<FlowKey, FlowMetrics>>>,
}

impl FlowTracker {
    pub fn new() -> Self {
        FlowTracker {
            flows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn process_packet(&self, packet: &RawPacket) -> Result<Vec<BehavioralPattern>> {
        let mut patterns = Vec::new();
        let flow_key = FlowKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
        };

        let mut flows = self.flows.lock().unwrap();
        let flow_metrics = flows.entry(flow_key.clone()).or_insert_with(|| FlowMetrics {
            first_seen: packet.timestamp,
            last_seen: packet.timestamp,
            packet_count: 0,
            byte_count: 0,
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
            average_packet_size: 0.0,
        });

        // Update flow metrics
        flow_metrics.last_seen = packet.timestamp;
        flow_metrics.packet_count += 1;
        flow_metrics.byte_count += packet.packet_size as u64;

        // Calculate rates
        let time_span = flow_metrics.last_seen - flow_metrics.first_seen;
        if time_span > 0 {
            flow_metrics.packets_per_second = flow_metrics.packet_count as f64 / (time_span as f64 / 1_000_000.0);
            flow_metrics.bytes_per_second = flow_metrics.byte_count as f64 / (time_span as f64 / 1_000_000.0);
        }
        flow_metrics.average_packet_size = flow_metrics.byte_count as f64 / flow_metrics.packet_count as f64;

        // Detect port scanning
        if flow_metrics.packet_count > 10 && flow_metrics.packets_per_second > 5.0 {
            patterns.push(BehavioralPattern {
                pattern_id: "PORT_SCAN".to_string(),
                pattern_type: PatternType::PortScan,
                confidence: 0.8,
                detection_time: packet.timestamp,
                flow_key: flow_key.clone(),
                metadata: HashMap::new(),
            });
        }

        // Detect DDoS
        if flow_metrics.packets_per_second > 100.0 {
            patterns.push(BehavioralPattern {
                pattern_id: "DDOS_ATTACK".to_string(),
                pattern_type: PatternType::DdosAttack,
                confidence: 0.9,
                detection_time: packet.timestamp,
                flow_key: flow_key.clone(),
                metadata: HashMap::new(),
            });
        }

        // Check for timing anomalies (bot-like behavior)
        if let Ok(Some(timing_anomaly)) = self.detect_timing_anomaly(&flow_key, flow_metrics) {
            patterns.push(timing_anomaly);
        }

        Ok(patterns)
    }

    fn detect_timing_anomaly(
        &self,
        flow_key: &FlowKey,
        flow_metrics: &FlowMetrics,
    ) -> Result<Option<BehavioralPattern>> {
        // Check for very regular timing (possible bot behavior)
        if flow_metrics.packet_count > 50 && flow_metrics.packets_per_second > 10.0 {
            let time_span = flow_metrics.last_seen - flow_metrics.first_seen;
            let expected_interval = time_span as f64 / flow_metrics.packet_count as f64;

            // Detect very regular timing
            if expected_interval > 0.0 {
                let regularity_score = 1.0 / (expected_interval.fract() + 0.1);

                if regularity_score > 8.0 {
                    let mut metadata = HashMap::new();
                    metadata.insert("regularity_score".to_string(), regularity_score.to_string());
                    metadata.insert(
                        "packets_per_second".to_string(),
                        flow_metrics.packets_per_second.to_string(),
                    );

                    return Ok(Some(BehavioralPattern {
                        pattern_id: "TIMING_REGULARITY_ANOMALY".to_string(),
                        pattern_type: PatternType::BotnetCommunication,
                        confidence: 0.6,
                        detection_time: flow_metrics.last_seen,
                        flow_key: flow_key.clone(),
                        metadata,
                    }));
                }
            }
        }
        Ok(None)
    }
}

// Main packet processing engine
pub struct PacketProcessor {
    dpi_engine: DpiEngine,
    flow_tracker: FlowTracker,
    threat_channel: Sender<ThreatIndicator>,
    pattern_channel: Sender<BehavioralPattern>,
    packet_stats: Arc<RwLock<PacketStats>>, 
}

#[derive(Debug, Default, Clone)]
pub struct PacketStats {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub last_update: Option<Instant>,
}

impl PacketProcessor {
    pub fn new(threat_tx: Sender<ThreatIndicator>, pattern_tx: Sender<BehavioralPattern>) -> Self {
        PacketProcessor {
            dpi_engine: DpiEngine::new(),
            flow_tracker: FlowTracker::new(),
            threat_channel: threat_tx,
            pattern_channel: pattern_tx,
            packet_stats: Arc::new(RwLock::new(PacketStats::default())), 
        }
    }

    pub async fn process_packet(&self, packet: RawPacket) -> Result<()> {
        // Update statistics
        self.update_stats(&packet);

        // Record metrics
        let counter = metrics::counter!("packets.processed", "type" => "processed");
        counter.increment(1);
        let histogram = metrics::histogram!("packet.size", "unit" => "bytes");
        histogram.record(packet.packet_size as f64);
        let gauge = metrics::gauge!("packets.in_flight", "status" => "active");
        gauge.set(1.0);

        // Deep packet inspection
        let dpi_patterns = self.dpi_engine.inspect_packet(&packet).context("DPI engine failed")?;
        let counter = metrics::counter!("patterns.dpi_detected", "source" => "dpi");
        counter.increment(dpi_patterns.len() as u64);

        // Flow tracking and behavioral analysis
        let flow_patterns = self.flow_tracker.process_packet(&packet).context("Flow tracking failed")?;
        let counter = metrics::counter!("patterns.flow_detected", "source" => "flow");
        counter.increment(flow_patterns.len() as u64);

        // Combine patterns
        let mut all_patterns = Vec::new();
        all_patterns.extend(dpi_patterns);
        all_patterns.extend(flow_patterns);
        let counter = metrics::counter!("patterns.total", "type" => "combined");
        counter.increment(all_patterns.len() as u64);

        // Send patterns to analysis pipeline
        for pattern in all_patterns {
            // Send pattern to pattern analysis
            if let Err(e) = self.pattern_channel.send(pattern.clone()) {
                error!("Failed to send pattern: {}", e);
                let counter = metrics::counter!("errors.pattern_channel", "channel" => "pattern");
                counter.increment(1);
            }
            
            // Convert pattern to threat and send to threat monitoring
            let threat = self.pattern_to_threat(&pattern);
            if let Err(e) = self.threat_channel.send(threat) {
                error!("Failed to send threat indicator: {}", e);
                let counter = metrics::counter!("errors.threat_channel", "channel" => "threat");
                counter.increment(1);
            }
        }

        let gauge = metrics::gauge!("packets.in_flight", "status" => "completed");
        gauge.set(-1.0);
        Ok(())
    }

    fn update_stats(&self, packet: &RawPacket) {
        let mut stats = self.packet_stats.write();
        stats.total_packets += 1;
        stats.total_bytes += packet.packet_size as u64; 

        let now = Instant::now();
        if let Some(last_update) = stats.last_update {
            if last_update.elapsed() >= Duration::from_secs(1) {
                let elapsed = last_update.elapsed().as_secs_f64();
                stats.packets_per_second = stats.total_packets as f64 / elapsed;
                stats.bytes_per_second = stats.total_bytes as f64 / elapsed;
                stats.last_update = Some(now); 
                
                // Update metrics
                let gauge = metrics::gauge!("packets.per_second", "unit" => "packets/s");
                gauge.set(stats.packets_per_second);
                let gauge = metrics::gauge!("bytes.per_second", "unit" => "bytes/s");
                gauge.set(stats.bytes_per_second);
            }
        } else {
            stats.last_update = Some(now);
        }
    }

    fn pattern_to_threat(&self, pattern: &BehavioralPattern) -> ThreatIndicator {
        let severity = match pattern.pattern_type {
            PatternType::DdosAttack => ThreatLevel::Critical,
            PatternType::Malware => ThreatLevel::Critical,
            PatternType::PortScan => ThreatLevel::High,
            PatternType::DataExfiltration => ThreatLevel::High,
            PatternType::BotnetCommunication => ThreatLevel::Medium,
            _ => ThreatLevel::Low, 
        };

        let description = match pattern.pattern_type {
            PatternType::DdosAttack => "DDoS attack detected",
            PatternType::Malware => "Malware communication detected",
            PatternType::PortScan => "Port scan activity detected",
            PatternType::DataExfiltration => "Potential data exfiltration detected",
            PatternType::BotnetCommunication => "Botnet communication detected",
            PatternType::AnomalousTraffic => "Anomalous traffic detected",
        }; 

        ThreatIndicator {
            severity,
            indicator_type: format!("{:?}", pattern.pattern_type),
            description: description.to_string(),
            source_ip: pattern.flow_key.src_ip,
            destination_ip: pattern.flow_key.dst_ip,
            timestamp: pattern.detection_time,
            evidence: vec![format!("Pattern ID: {}", pattern.pattern_id)], 
        }
    }

    pub fn get_stats(&self) -> PacketStats {
        self.packet_stats.read().clone()
    }
}

// Packet generator for testing/demo 
#[derive(Clone)]
pub struct PacketGenerator {
    packet_sender: Sender<RawPacket>, 
}

impl PacketGenerator {
    pub fn new(packet_sender: Sender<RawPacket>) -> Self {
        PacketGenerator { packet_sender } 
    }

    pub async fn start_generation(&self) {
        let mut counter = 0u64;
        let mut interval = tokio::time::interval(Duration::from_millis(10));

        loop {
            interval.tick().await;
            counter += 1;

            let packet = self.generate_packet(counter);
            if self.packet_sender.send(packet).is_err() {
                error!("Failed to send generated packet");
                break; 
            }
        }
    }

    fn generate_packet(&self, counter: u64) -> RawPacket {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;

        // Generate different types of packets for testing
        let packet_type = counter % 10;

        match packet_type {
            // Normal HTTP traffic
            0..=6 => RawPacket {
                timestamp,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, ((counter % 50) + 10) as u8)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, ((counter % 10) + 1) as u8)),
                src_port: (32768 + (counter % 30000)) as u16,
                dst_port: 80,
                protocol: 6, // TCP
                payload: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
                packet_size: 200 + ((counter % 800) as usize), 
            },
            // Suspicious large POST (potential data exfiltration)
            7 => RawPacket {
                timestamp,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                src_port: 45678,
                dst_port: 443,
                protocol: 6,
                payload: vec![b'X'; 15000], // Large Payload
                packet_size: 15000, 
            },
            // Port scan pattern
            8 => RawPacket {
                timestamp,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)), // Same source
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: 54321,
                dst_port: (80 + (counter % 100)) as u16, // Different destination ports 
                protocol: 6,
                payload: b"".to_vec(),
                packet_size: 60, 
            },
            // Bot-like regular traffic 
            9 => RawPacket {
                timestamp,
                src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 50)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), // Some external IP 
                src_port: 12345,
                dst_port: 80,
                protocol: 6,
                payload: b"GET /beacon HTTP/1.1\r\nUser-Agent: bot\r\n\r\n".to_vec(), 
                packet_size: 100, 
            },
            _ => unreachable!(), 
        }
    }
}

// Main processing engine
pub struct TrafficAnalysisEngine {
    packet_processor: PacketProcessor,
    packet_generator: PacketGenerator,
    threat_receiver: Receiver<ThreatIndicator>,
    pattern_receiver: Receiver<BehavioralPattern>,
    packet_receiver: Receiver<RawPacket>, 
}

impl TrafficAnalysisEngine {
    pub fn new() -> Self {
        let (threat_tx, threat_rx) = mpsc::channel();
        let (pattern_tx, pattern_rx) = mpsc::channel();
        let (packet_tx, packet_rx) = mpsc::channel(); 

        let packet_processor = PacketProcessor::new(threat_tx, pattern_tx);
        let packet_generator = PacketGenerator::new(packet_tx);

        TrafficAnalysisEngine {
            packet_processor,
            packet_generator,
            threat_receiver: threat_rx,
            pattern_receiver: pattern_rx,
            packet_receiver: packet_rx, 
        }
    }

    pub async fn start(&mut self) {
        info!("Starting Rust traffic analysis engine");

        // Start packet generation
        let generator = self.packet_generator.clone();
        tokio::spawn(async move {
            generator.start_generation().await; 
        });

        // Start threat monitoring 
        let threat_rx = std::mem::replace(&mut self.threat_receiver, mpsc::channel().1);
        tokio::spawn(async move {
            Self::threat_monitoring_loop(threat_rx).await;  
        });

        // Start pattern monitoring
        let pattern_rx = std::mem::replace(&mut self.pattern_receiver, mpsc::channel().1);
        tokio::spawn(async move {
            Self::pattern_monitoring_loop(pattern_rx).await; 
        });

        // Main packet processing loop
        let packet_rx = std::mem::replace(&mut self.packet_receiver, mpsc::channel().1);
        loop {
            match packet_rx.recv() {
                Ok(packet) => {
                    if let Err(e) = self.packet_processor.process_packet(packet).await {
                        error!("Failed to process packet: {}", e); 
                    }
                }
                Err(_) => {
                    info!("Packet channel closed, stopping engine"); 
                    break; 
                }
            }
        }
    }
    async fn threat_monitoring_loop(receiver: Receiver<ThreatIndicator>) {
        while let Ok(threat) = receiver.recv() {
            match threat.severity {
                ThreatLevel::Critical => {
                    error!("CRITICAL THREAT DETECTED: {} from {} to {}", threat.description, threat.source_ip, threat.destination_ip); 
                }
                ThreatLevel::High => {
                    warn!("HIGH THREAT DETECTED: {} from {} to {}", threat.description, threat.source_ip, threat.destination_ip); 
                }
                ThreatLevel::Medium => {
                    info!("MEDIUM THREAT DETECTED: {} from {} to {}", threat.description, threat.source_ip, threat.destination_ip); 
                }
                ThreatLevel::Low => {
                    debug!("LOW THREAT DETECTED: {} from {} to {}", threat.description, threat.source_ip, threat.destination_ip); 
                }
            }
        }
    }

    async fn pattern_monitoring_loop(receiver: Receiver<BehavioralPattern>) {
        let mut pattern_counts = HashMap::new();

        while let Ok(pattern) = receiver.recv() {
            *pattern_counts.entry(format!("{:?}", pattern.pattern_type)).or_insert(0) += 1; 

            debug!("Pattern detected: {:?} (confidence: {:.2})",
               pattern.pattern_type, pattern.confidence);

            // Log Pattern statistics every 50 patterns
            if pattern_counts.values().sum::<u32>() % 50 == 0 {
                info!("Pattern statistics: {:?}", pattern_counts);  
            }
        }
    }
}

// Include test module
#[cfg(test)]
mod tests;

// Main function
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing with better configuration
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Initialize metrics (commented out due to API compatibility issues)
    // #[cfg(feature = "metrics-exporter-prometheus")]
    // {
    //     metrics_exporter_prometheus::PrometheusBuilder::new()
    //         .with_endpoint("127.0.0.1:9000")
    //         .install()
    //         .expect("Failed to install Prometheus metrics exporter");
    // }

    info!("Starting Rust packet processor with enhanced monitoring");

    // Create and start the traffic analysis engine
    let mut engine = TrafficAnalysisEngine::new();

    // Start the engine
    engine.start().await;

    Ok(()) 
}