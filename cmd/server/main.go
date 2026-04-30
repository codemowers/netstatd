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
	"strings"
	"syscall"
	"time"

	"netstatd/internal/containerd"
	"netstatd/internal/ebpf"
	"netstatd/internal/server"
)

func main() {
	// Parse command line flags
	logLevel := flag.String("log-level", "warn", "Log level: trace, debug, info, warn, error")
	httpPort := flag.String("http-port", "5280", "HTTP port for single-pod server")
	httpMuxPort := flag.String("http-mux-port", "6280", "HTTP port for multiplexer server")
	disableTCP := flag.Bool("disable-tcp", false, "Disable TCP connection monitoring")
	enableUDP := flag.Bool("enable-udp", false, "Enable UDP connection monitoring")

	// Work around Docker/containerd issue where os.Args[1] is the program name again
	// If os.Args[1] looks like a program path, skip it
	if len(os.Args) > 1 && (os.Args[1] == "./netstatd" || os.Args[1] == "/netstatd" || os.Args[1] == "netstatd") {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}

	// Parse flags FIRST before using any flag values
	flag.Parse()

	// Validate that flags were actually parsed
	// If there are unparsed arguments, the flags weren't recognized
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "Error: Unexpected arguments after flags: %v\n", flag.Args())
		fmt.Fprintf(os.Stderr, "os.Args was: %v\n", os.Args)
		fmt.Fprintf(os.Stderr, "\nUsage:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "os.Args: %v\n", os.Args)
	fmt.Fprintf(os.Stderr, "Parsed flags:\n")
	fmt.Fprintf(os.Stderr, "  disable-tcp=%v\n", *disableTCP)
	fmt.Fprintf(os.Stderr, "  enable-udp=%v\n", *enableUDP)
	fmt.Fprintf(os.Stderr, "  log-level=%v\n", *logLevel)

	// Set up structured logging with slog
	// Define custom TRACE level (lower than DEBUG)
	const LevelTrace = slog.Level(-8)

	var level slog.Level
	switch strings.ToLower(*logLevel) {
	case "trace":
		level = LevelTrace
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		fmt.Fprintf(os.Stderr, "Unknown log level '%s', defaulting to 'info'\n", *logLevel)
		level = slog.LevelInfo
	}

	fmt.Fprintf(os.Stderr, "Setting log level to: %v (numeric: %d)\n", level, level)
	fmt.Fprintf(os.Stderr, "Command line flags: http-port=%s http-mux-port=%s disable-tcp=%v enable-udp=%v\n",
		*httpPort, *httpMuxPort, *disableTCP, *enableUDP)

	// Build config bitmap
	var configFlags uint32
	if *disableTCP {
		configFlags |= ebpf.ConfigDisableTCP
	}
	if !*enableUDP {
		configFlags |= ebpf.ConfigDisableUDP
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Remove timestamp from logs
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
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

	slog.Debug("Log level set", "level", *logLevel)

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

	// Get fanout service from environment (optional)
	fanoutService := os.Getenv("FANOUT_SERVICE")

	// Create HTTP listener for multiplexer server only if FANOUT_SERVICE is set
	var muxListener net.Listener
	if fanoutService != "" {
		muxAddr := fmt.Sprintf("[::]:%s", *httpMuxPort)
		muxListener, err = net.Listen("tcp", muxAddr)
		if err != nil {
			slog.Error("Failed to listen", "addr", muxAddr, "error", err)
			os.Exit(1)
		}
		slog.Info("Multiplexer HTTP server listening", "addr", muxAddr, "fanoutService", fanoutService)
		slog.Debug("Multiplexer endpoints",
			"http", fmt.Sprintf("http://[::]:%s", *httpMuxPort),
			"websocket", fmt.Sprintf("ws://[::]:%s/netstat", *httpMuxPort),
		)
	} else {
		slog.Info("FANOUT_SERVICE not set, multiplexer server disabled")
	}

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
	fmt.Fprintf(os.Stderr, "Initializing eBPF tracer: disableTCP=%v enableUDP=%v configFlags=0x%x\n", *disableTCP, *enableUDP, configFlags)
	tracer, err := ebpf.NewTracer(configFlags)
	if err != nil {
		slog.Error("Failed to create eBPF tracer", "error", err)
		os.Exit(1)
	}
	defer tracer.Close()
	slog.Debug("eBPF tracer initialized successfully")

	// Initialize HTTP/WebSocket server
	srv := server.NewServer(ctrdClient, tracer, fanoutService)

	slog.Info("All ports are now listening and ready to accept connections")
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

	// Start multiplexer server only if FANOUT_SERVICE is set
	if fanoutService != "" {
		go func() {
			slog.Info("Multiplexer HTTP server starting...")
			err := srv.StartMuxWithListener(muxListener)
			if err != nil && err != http.ErrServerClosed {
				slog.Error("Multiplexer server error", "error", err)
				os.Exit(1)
			}
			slog.Info("Multiplexer HTTP server stopped")
		}()
	}

	// Give servers a tiny moment to start accepting
	time.Sleep(50 * time.Millisecond)

	slog.Info("HTTP servers are now accepting connections")
	slog.Debug("Server is fully operational")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	slog.Info("Shutting down...")
	srv.Shutdown(ctx)
}
