// Command xhelix-sinkhole is the static sinkhole binary. The eBPF
// socket-redirect program (P-PS.7b, follow-on) points forbidden
// outbound connect() syscalls at this listener. Until P-PS.7b
// lands, operators can integration-test by manually pointing a
// suspect process at the bound ports.
//
// Pure Go. CGO_ENABLED=0.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/xhelix/xhelix/pkg/deception/sinkhole"
)

func main() {
	httpAddr := flag.String("http", "127.0.0.1:8081", "address for the HTTP listener")
	tlsAddr := flag.String("tls", "127.0.0.1:8443", "address for the TLS listener")
	rawAddr := flag.String("raw", "127.0.0.1:14444", "address for the raw-TCP listener (empty to disable)")
	logPath := flag.String("log", os.Getenv("XHELIX_SINKHOLE_LOG"), "JSON-lines forensic log path (default: stderr)")
	flag.Parse()

	logger, closer, err := openLogger(*logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xhelix-sinkhole: log open:", err)
		os.Exit(2)
	}
	if closer != nil {
		defer closer.Close()
	}

	cfg := sinkhole.Config{
		Logger: logger,
	}
	if *httpAddr != "" {
		cfg.Ports = append(cfg.Ports, sinkhole.PortConfig{Addr: *httpAddr, Mode: sinkhole.ModeHTTP})
	}
	if *tlsAddr != "" {
		cfg.Ports = append(cfg.Ports, sinkhole.PortConfig{Addr: *tlsAddr, Mode: sinkhole.ModeTLS})
	}
	if *rawAddr != "" {
		cfg.Ports = append(cfg.Ports, sinkhole.PortConfig{Addr: *rawAddr, Mode: sinkhole.ModeRaw})
	}
	if len(cfg.Ports) == 0 {
		fmt.Fprintln(os.Stderr, "xhelix-sinkhole: no ports configured")
		os.Exit(2)
	}

	l, err := sinkhole.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xhelix-sinkhole: new:", err)
		os.Exit(2)
	}
	if err := l.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "xhelix-sinkhole: start:", err)
		os.Exit(2)
	}

	var addrs []string
	for _, a := range l.Addrs() {
		addrs = append(addrs, a.String())
	}
	fmt.Fprintf(os.Stderr, "xhelix-sinkhole: listening on %s\n", strings.Join(addrs, ", "))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = l.Stop()
}

func openLogger(logPath string) (sinkhole.Logger, io.Closer, error) {
	if fdStr := os.Getenv("XHELIX_SINKHOLE_LOG_FD"); fdStr != "" {
		fd, err := strconv.Atoi(fdStr)
		if err != nil {
			return nil, nil, fmt.Errorf("bad XHELIX_SINKHOLE_LOG_FD: %w", err)
		}
		f := os.NewFile(uintptr(fd), fmt.Sprintf("sinkhole-log-fd-%d", fd))
		if f == nil {
			return nil, nil, fmt.Errorf("could not open fd %d", fd)
		}
		return sinkhole.NewJSONLLogger(f), f, nil
	}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, err
		}
		return sinkhole.NewJSONLLogger(f), f, nil
	}
	return sinkhole.NewJSONLLogger(os.Stderr), nil, nil
}
