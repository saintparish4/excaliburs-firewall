package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Core structures for traffic analysis
type ThreatLevel string

const (
	ThreatLow      ThreatLevel = "low"
	ThreatMedium   ThreatLevel = "medium"
	ThreatHigh     ThreatLevel = "high"
	ThreatCritical ThreatLevel = "critical"
)

type ThreatIndicator struct {
	ID          string      `json:"id"`
	Severity    ThreatLevel `json:"severity"`
	Type        string      `json:"type"`
	Description string      `json:"description"`
	SourceIP    string      `json:"source_ip"`
	DestIP      string      `json:"dest_ip"`
	Timestamp   time.Time   `json:"timestamp"`
	Evidence    []string    `json:"evidence"`
	Confidence  float64     `json:"confidence"`
}

type BehavioralPattern struct {
	PatternID     string            `json:"pattern_id"`
	PatternType   string            `json:"pattern_type"`
	Confidence    float64           `json:"confidence"`
	DetectionTime time.Time         `json:"detection_time"`
	FlowKey       FlowKey           `json:"flow_key"`
	Metadata      map[string]string `json:"metadata"`
}

type FlowKey struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"`
}

type PacketStats struct {
	TotalPackets      uint64  `json:"total_packets"`
	TotalBytes        uint64  `json:"total_bytes"`
	PacketsPerSecond  float64 `json:"packets_per_second"`
	BytesPerSecond    float64 `json:"bytes_per_second"`
	ThreatsDetected   uint64  `json:"threats_detected"`
	PatterrnsDetected uint64  `json:"patterns_detected"`
}

// Prometheus metrics
var (
	packetsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "firewall_packets_processed_total",
			Help: "Total number of packets processed",
		},
		[]string{"protocol"},
	)

	threatsDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "firewall_threats_detected_total",
			Help: "Total number of threats detected",
		},
		[]string{"severity", "type"},
	)

	activeFlows = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "firewall_active_flows",
			Help: "Number of active network flows",
		},
	)

	processingLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "firewall_processing_latency_seconds",
			Help: "Latency of packet processing",
		},
		[]string{"stage"},
	)
)

func init() {
	prometheus.MustRegister(packetsProcessed)
	prometheus.MustRegister(threatsDetected)
	prometheus.MustRegister(activeFlows)
	prometheus.MustRegister(processingLatency)
}

// Main firewall engine
type FirewallEngine struct {
	logger       *zap.Logger
	stats        *PacketStats
	statsMutex   sync.RWMutex
	clients      map[*websocket.Conn]bool
	clientsMutex sync.RWMutex
	upgrader     websocket.Upgrader
	rustProcess  *exec.Cmd
	threatChan   chan ThreatIndicator
	patternChan  chan BehavioralPattern
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewFirewallEngine(logger *zap.Logger) *FirewallEngine {
	ctx, cancel := context.WithCancel(context.Background())

	return &FirewallEngine{
		logger:  logger,
		stats:   &PacketStats{TotalPackets: 0, TotalBytes: 0, PacketsPerSecond: 0, BytesPerSecond: 0, ThreatsDetected: 0, PatterrnsDetected: 0},
		clients: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for development
			},
		},
		threatChan:  make(chan ThreatIndicator, 1000),
		patternChan: make(chan BehavioralPattern, 1000),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start the firewall engine
func (fe *FirewallEngine) Start() error {
	fe.logger.Info("Starting firewall engine")

	// Start the Rust packet processor
	if err := fe.startRustProcessor(); err != nil {
		return fmt.Errorf("failed to start Rust processor: %w", err)
	}

	// Start background processors
	go fe.processThreatIndicators()
	go fe.processBehavioralPatterns()
	go fe.updateStatistics()
	go fe.broadcastUpdates()

	fe.logger.Info("Firewall engine started successfully")
	return nil
}

// Start the Rust packet processing component
func (fe *FirewallEngine) startRustProcessor() error {
	fe.logger.Info("Starting Rust packet processor")

	// In a real implementation, you would compile and run the Rust binary
	// For this demo, we'll simulate the Rust process
	fe.rustProcess = exec.CommandContext(fe.ctx, "echo", "Rust processor simulation")

	// Start generating simualted traffic for demo purposes
	go fe.simulateTrafficProcessing()

	return nil
}

// Simulate traffic processing for demo purposes
func (fe *FirewallEngine) simulateTrafficProcessing() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	threatTypes := []string{"port_scan", "ddos_attack", "malware", "data_exfiltration", "botnet"}
	severities := []ThreatLevel{ThreatLow, ThreatMedium, ThreatHigh, ThreatCritical}

	for {
		select {
		case <-fe.ctx.Done():
			return
		case <-ticker.C:
			// Simulate packet processing
			fe.statsMutex.Lock()
			fe.stats.TotalPackets += uint64(50 + (time.Now().UnixNano() % 100))
			fe.stats.TotalBytes += uint64(1500 + (time.Now().UnixNano() % 3000))
			fe.statsMutex.Unlock()

			packetsProcessed.WithLabelValues("tcp").Add(30)
			packetsProcessed.WithLabelValues("udp").Add(15)
			packetsProcessed.WithLabelValues("icmp").Add(5)

			// Occasionally generate threats
			if time.Now().UnixNano()%10 == 0 {
				threat := ThreatIndicator{
					ID:          fmt.Sprintf("threat_%d", time.Now().UnixNano()),
					Severity:    severities[time.Now().UnixNano()%int64(len(severities))],
					Type:        threatTypes[time.Now().UnixNano()%int64(len(threatTypes))],
					Description: "Suspicious network activity detected",
					SourceIP:    fmt.Sprintf("192.168.1.%d", 10+(time.Now().UnixNano()%240)),
					DestIP:      fmt.Sprintf("10.0.0.%d", 1+(time.Now().UnixNano()%254)),
					Timestamp:   time.Now(),
					Evidence:    []string{"High packet rate", "Unusual port scanning pattern"},
					Confidence:  0.7 + (float64(time.Now().UnixNano()%30) / 100.0),
				}

				select {
				case fe.threatChan <- threat:
					threatsDetected.WithLabelValues(string(threat.Severity), threat.Type).Inc()
				default:
					fe.logger.Warn("Threat channel full, dropping threat")
				}
			}

			// Generate behavioral patterns
			if time.Now().UnixNano()%5 == 0 {
				pattern := BehavioralPattern{
					PatternID:     fmt.Sprintf("pattern_%d", time.Now().UnixNano()),
					PatternType:   "anomalous_traffic",
					Confidence:    0.6 + (float64(time.Now().UnixNano()%40) / 100.0),
					DetectionTime: time.Now(),
					FlowKey: FlowKey{
						SrcIP:    fmt.Sprintf("192.168.1.%d", 10+(time.Now().UnixNano()%240)),
						DstIP:    fmt.Sprintf("10.0.0.%d", 1+(time.Now().UnixNano()%254)),
						SrcPort:  uint16(1024 + (time.Now().UnixNano() % 60000)),
						DstPort:  uint16(80 + (time.Now().UnixNano() % 8000)),
						Protocol: 6, // TCP
					},
					Metadata: map[string]string{
						"bytes_per_second": fmt.Sprintf("%.2f", 1000+float64(time.Now().UnixNano()%10000)),
						"packet_count":     fmt.Sprintf("%d", 10+(time.Now().UnixNano()%100)),
					},
				}

				select {
				case fe.patternChan <- pattern:
				default:
					fe.logger.Warn("Pattern channel full, dropping pattern")
				}
			}
		}
	}
}

// Process threat indicators
func (fe *FirewallEngine) processThreatIndicators() {
	for {
		select {
		case <-fe.ctx.Done():
			return
		case threat := <-fe.threatChan:
			fe.handleThreat(threat)
		}
	}
}

// Handle individual threats
func (fe *FirewallEngine) handleThreat(threat ThreatIndicator) {
	fe.logger.Info(
		"Processing threat",
		zap.String("id", threat.ID),
		zap.String("severity", string(threat.Severity)),
		zap.String("type", threat.Type),
		zap.String("source_ip", threat.SourceIP),
		zap.Float64("confidence", threat.Confidence),
	)

	fe.statsMutex.Lock()
	fe.stats.ThreatsDetected++
	fe.statsMutex.Unlock()

	// Implement blocking logic for critical threats
	if threat.Severity == ThreatCritical {
		fe.blockIP(threat.SourceIP)
	}

	// Broadcast to connected clients
	fe.broadcastThreat(threat)
}

// Block IP address (simiplified implementation)
func (fe *FirewallEngine) blockIP(ip string) {
	fe.logger.Warn("Blocking IP address", zap.String("ip", ip))

	// In a real implementation you would:
	// 1. Add iptables rule
	// 2. Update eBPF maps
	// 3. Notify other firewall components

	// For demo, I'll just log it
	fe.logger.Info("IP blocked successfully", zap.String("ip", ip))
}

// Process behavioral patterns
func (fe *FirewallEngine) processBehavioralPatterns() {
	for {
		select {
		case <-fe.ctx.Done():
			return 
		case pattern := <-fe.patternChan:
			fe.handlePattern(pattern) 
		}
	}
}

// Handle behavioral patterns
func (fe *FirewallEngine) handlePattern(pattern BehavioralPattern) {
	fe.logger.Debug("Processing behavioral pattern",
	 zap.String("pattern_id", pattern.PatternID),
	 zap.String("type", pattern.PatternType),
	 zap.Float64("confidence", pattern.Confidence), 
    )

	fe.statsMutex.Lock()
	fe.stats.PatterrnsDetected++
	fe.statsMutex.Unlock()

	// Convert high-confidence patterns to threats
	if pattern.Confidence > 0.8 {
		threat := fe.patternToThreat(pattern)
		select {
		case fe.threatChan <- threat:
		default:
			fe.logger.Warn("Could not convert pattern to threat - channel full")
		}
	}
}

// Convert pattern to threat
func (fe *FirewallEngine) patternToThreat(pattern BehavioralPattern) ThreatIndicator {
	var severity ThreatLevel
	switch pattern.PatternType {
	case "ddos_attack", "malware":
		severity = ThreatCritical
	case "port_scan", "data_exfiltration":
		severity = ThreatHigh
	case "botnet_communication":
		severity = ThreatMedium
	default:
		severity = ThreatLow
	}
	
	return ThreatIndicator{
		ID:          fmt.Sprintf("threat_from_pattern_%s", pattern.PatternID),
		Severity:    severity,
		Type:        pattern.PatternType,
		Description: fmt.Sprintf("Pattern-based detection: %s", pattern.PatternType),
		SourceIP:    pattern.FlowKey.SrcIP,
		DestIP:      pattern.FlowKey.DstIP,
		Timestamp:   pattern.DetectionTime,
		Evidence:    []string{fmt.Sprintf("Behavioral pattern %s detected", pattern.PatternID)},
		Confidence:  pattern.Confidence,
	}
}

// Update statistics periodically
func (fe *FirewallEngine) updateStatistics() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	var lastPackets, lastBytes uint64
	var lastTime time.Time = time.Now()
	
	for {
		select {
		case <-fe.ctx.Done():
			return
		case <-ticker.C:
			fe.statsMutex.Lock()
			
			now := time.Now()
			duration := now.Sub(lastTime).Seconds()
			
			if duration > 0 {
				fe.stats.PacketsPerSecond = float64(fe.stats.TotalPackets-lastPackets) / duration
				fe.stats.BytesPerSecond = float64(fe.stats.TotalBytes-lastBytes) / duration
			}
			
			lastPackets = fe.stats.TotalPackets
			lastBytes = fe.stats.TotalBytes
			lastTime = now
			
			// Update Prometheus metrics
			activeFlows.Set(float64(100 + (time.Now().UnixNano() % 1000))) // Simulated
			
			fe.statsMutex.Unlock()
		}
	}
}

// Broadcast updates to WebSocket clients
func (fe *FirewallEngine) broadcastUpdates() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-fe.ctx.Done():
			return
		case <-ticker.C:
			fe.broadcastStats()
		}
	}
}

// Broadcast current statistics
func (fe *FirewallEngine) broadcastStats() {
	fe.statsMutex.RLock()
	stats := *fe.stats
	fe.statsMutex.RUnlock()
	
	message := map[string]interface{}{
		"type": "stats",
		"data": stats,
	}
	
	fe.broadcastToClients(message)
}

// Broadcast threat to clients
func (fe *FirewallEngine) broadcastThreat(threat ThreatIndicator) {
	message := map[string]interface{}{
		"type": "threat",
		"data": threat,
	}
	
	fe.broadcastToClients(message)
}

// Broadcast message to all WebSocket clients
func (fe *FirewallEngine) broadcastToClients(message interface{}) {
	fe.clientsMutex.RLock()
	defer fe.clientsMutex.RUnlock()
	
	data, err := json.Marshal(message)
	if err != nil {
		fe.logger.Error("Failed to marshal message", zap.Error(err))
		return
	}
	
	for client := range fe.clients {
		err := client.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			fe.logger.Error("Failed to write to client", zap.Error(err))
			client.Close()
			delete(fe.clients, client)
		}
	}
}

// HTTP Handlers
func (fe *FirewallEngine) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := fe.upgrader.Upgrade(w, r, nil)
	if err != nil {
		fe.logger.Error("WebSocket upgrade failed", zap.Error(err))
		return
	}
	
	fe.clientsMutex.Lock()
	fe.clients[conn] = true
	fe.clientsMutex.Unlock()
	
	fe.logger.Info("New WebSocket client connected")
	
	// Send current stats immediately
	fe.broadcastStats()
	
	// Handle client disconnection
	defer func() {
		fe.clientsMutex.Lock()
		delete(fe.clients, conn)
		fe.clientsMutex.Unlock()
		conn.Close()
		fe.logger.Info("WebSocket client disconnected")
	}()
	
	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (fe *FirewallEngine) handleStats(w http.ResponseWriter, r *http.Request) {
	fe.statsMutex.RLock()
	stats := *fe.stats
	fe.statsMutex.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (fe *FirewallEngine) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (fe *FirewallEngine) handleBlock(w http.ResponseWriter, r *http.Request) {
	var request struct {
		IP string `json:"ip"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	fe.blockIP(request.IP)
	
	response := map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("IP %s blocked successfully", request.IP),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Stop the firewall engine
func (fe *FirewallEngine) Stop() {
	fe.logger.Info("Stopping firewall engine")
	fe.cancel()
	
	if fe.rustProcess != nil {
		fe.rustProcess.Process.Kill()
	}
	
	fe.logger.Info("Firewall engine stopped")
}

// Main function
func main() {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal("Failed to initialize logger:", err)
	}
	defer logger.Sync()
	
	// Create firewall engine
	engine := NewFirewallEngine(logger)
	
	// Start the engine
	if err := engine.Start(); err != nil {
		logger.Fatal("Failed to start firewall engine", zap.Error(err))
	}
	
	// Setup HTTP routes
	router := mux.NewRouter()
	
	// API routes
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/stats", engine.handleStats).Methods("GET")
	api.HandleFunc("/health", engine.handleHealth).Methods("GET")
	api.HandleFunc("/block", engine.handleBlock).Methods("POST")
	api.HandleFunc("/ws", engine.handleWebSocket)
	
	// Metrics endpoint
	router.Handle("/metrics", promhttp.Handler())
	
	// Static files (dashboard)
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))
	
	// Start HTTP server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	
	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		logger.Info("Starting HTTP server on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP server failed", zap.Error(err))
		}
	}()
	
	// Wait for shutdown signal
	<-sigChan
	logger.Info("Shutdown signal received")
	
	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	engine.Stop()
	server.Shutdown(ctx)
	
	logger.Info("Server shutdown complete")
}