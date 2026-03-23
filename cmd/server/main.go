package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netstatd/internal/containerd"
	"netstatd/internal/dnstap"
	"netstatd/internal/ebpf"
	"netstatd/internal/server"
)

func main() {
	// Parse command line flags
	logLevel := flag.String("log-level", "info", "Log level: trace, debug, info, warn, error")
	httpPort := flag.String("http-port", "5280", "HTTP port for single-pod server")
	httpMuxPort := flag.String("http-mux-port", "6280", "HTTP port for multiplexer server")
	dnstapPort := flag.String("dnstap-port", "5253", "DNSTap port for single-pod server")
	dnstapMuxPort := flag.String("dnstap-mux-port", "6253", "DNSTap port for multiplexer server")
	disableTCP := flag.Bool("disable-tcp", false, "Disable TCP connection monitoring")
	enableUDP := flag.Bool("enable-udp", false, "Enable UDP connection monitoring")
	flag.Parse()

	// Set up structured logging with slog
	// Define custom TRACE level (lower than DEBUG)
	const LevelTrace = slog.Level(-8)

	var level slog.Level
	switch *logLevel {
	case "trace":
		level = LevelTrace
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey {
				level := a.Value.Any().(slog.Level)
				if level == LevelTrace {
					a.Value = slog.StringValue("TRACE")
				}
			}
			return a
		},
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Create all listeners FIRST before starting any goroutines
	// This ensures ports are bound immediately

	// Create HTTP listener for single-pod server
	httpAddr := fmt.Sprintf("[::]:%s", *httpPort)
	httpListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		slog.Error("Failed to listen", "addr", httpAddr, "error", err)
		os.Exit(1)
	}
	slog.Info("Single-pod HTTP server listening", "addr", httpAddr)
	slog.Debug("Single-pod endpoints",
		"http", fmt.Sprintf("http://[::]:%s", *httpPort),
		"websocket", fmt.Sprintf("ws://[::]:%s/netstat", *httpPort),
	)

	// Create HTTP listener for multiplexer server
	muxAddr := fmt.Sprintf("[::]:%s", *httpMuxPort)
	muxListener, err := net.Listen("tcp", muxAddr)
	if err != nil {
		slog.Error("Failed to listen", "addr", muxAddr, "error", err)
		os.Exit(1)
	}
	slog.Info("Multiplexer HTTP server listening", "addr", muxAddr)
	slog.Debug("Multiplexer endpoints",
		"http", fmt.Sprintf("http://[::]:%s", *httpMuxPort),
		"websocket", fmt.Sprintf("ws://[::]:%s/netstat", *httpMuxPort),
	)

	// Get containerd socket from environment or use default
	containerdSocket := os.Getenv("CONTAINERD_SOCKET")
	if containerdSocket == "" {
		containerdSocket = "/run/containerd/containerd.sock"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize containerd client
	ctrdClient, err := containerd.NewClient(ctx, containerdSocket)
	if err != nil {
		slog.Error("Failed to create containerd client", "error", err)
		os.Exit(1)
	}
	defer ctrdClient.Close()

	// Initialize eBPF tracer
	disableUDP := !*enableUDP
	slog.Debug("Initializing eBPF tracer", "disableTCP", *disableTCP, "enableUDP", *enableUDP)
	tracer, err := ebpf.NewTracer(*disableTCP, disableUDP)
	if err != nil {
		slog.Error("Failed to create eBPF tracer", "error", err)
		os.Exit(1)
	}
	defer tracer.Close()
	slog.Debug("eBPF tracer initialized successfully")

	// Initialize HTTP/WebSocket server (but don't start event processing yet)
	srv := server.NewServer(ctrdClient, tracer)

	// Create DNSTap collectors (non-fatal if they fail)
	dnstapCollector, err := dnstap.NewCollector(fmt.Sprintf("[::]:%s", *dnstapPort), srv.GetDNSCache())
	if err != nil {
		slog.Warn("Failed to create DNSTap collector", "port", *dnstapPort, "error", err)
	} else {
		slog.Info("DNSTap collector listening", "addr", fmt.Sprintf("[::]:%s", *dnstapPort))
	}

	dnstapMuxCollector, err := dnstap.NewCollector(fmt.Sprintf("[::]:%s", *dnstapMuxPort), srv.GetDNSCache())
	if err != nil {
		slog.Warn("Failed to create DNSTap mux collector", "port", *dnstapMuxPort, "error", err)
	} else {
		slog.Info("DNSTap mux collector listening", "addr", fmt.Sprintf("[::]:%s", *dnstapMuxPort))
	}

	slog.Info("All ports are now listening and ready to accept connections")
	slog.Info("Starting HTTP servers...")

	// Start servers immediately
	slog.Info("Starting HTTP servers...")

	// Start single-pod server
	go func() {
		slog.Info("Single-pod HTTP server starting...")
		err := srv.StartWithListener(httpListener)
		if err != nil && err != http.ErrServerClosed {
			slog.Error("Single-pod server error", "error", err)
			os.Exit(1)
		}
		slog.Info("Single-pod HTTP server stopped")
	}()

	// Start multiplexer server
	go func() {
		slog.Info("Multiplexer HTTP server starting...")
		err := srv.StartMuxWithListener(muxListener)
		if err != nil && err != http.ErrServerClosed {
			slog.Error("Multiplexer server error", "error", err)
			os.Exit(1)
		}
		slog.Info("Multiplexer HTTP server stopped")
	}()

	// Give servers a tiny moment to start accepting
	time.Sleep(50 * time.Millisecond)

	slog.Info("HTTP servers are now accepting connections")
	slog.Debug("Server is fully operational")

	// Start DNSTap collectors if they were created successfully
	if dnstapCollector != nil {
		go dnstapCollector.Start()
	}
	if dnstapMuxCollector != nil {
		go dnstapMuxCollector.Start()
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	slog.Info("Shutting down...")
	srv.Shutdown(ctx)
}
