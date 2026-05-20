// Command xhelix-dnspoison is the static DNS-shim binary for Ring 2
// outbound deception. Forbidden / DGA-shaped DNS lookups resolve to
// the sinkhole IP; everything else is forwarded transparently.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/xhelix/xhelix/pkg/deception/dnspoison"
)

func main() {
	udpAddr := flag.String("udp", "127.0.0.1:5353", "UDP bind address")
	tcpAddr := flag.String("tcp", "", "optional TCP bind address (empty = disabled)")
	upstream := flag.String("upstream", "1.1.1.1:53", "upstream resolver for pass-through queries; empty = NXDOMAIN")
	sinkIP := flag.String("sink-ip", "127.0.0.1", "IPv4 address poisoned A queries resolve to")
	knownBadFile := flag.String("known-bad", os.Getenv("XHELIX_DNSPOISON_KNOWN_BAD"),
		"path to newline-delimited known-bad domain list (substring match)")
	logPath := flag.String("log", os.Getenv("XHELIX_DNSPOISON_LOG"), "JSON-lines forensic log path (default: stderr)")
	logPass := flag.Bool("log-passthrough", false, "also log non-poisoned (forwarded) queries")
	flag.Parse()

	ip := net.ParseIP(*sinkIP)
	if ip == nil || ip.To4() == nil {
		fmt.Fprintln(os.Stderr, "xhelix-dnspoison: -sink-ip must be a valid IPv4 address")
		os.Exit(2)
	}

	cl := dnspoison.NewClassifier()
	if *knownBadFile != "" {
		domains, err := readDomainList(*knownBadFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xhelix-dnspoison: read %s: %v\n", *knownBadFile, err)
			os.Exit(2)
		}
		cl.SetKnownBad(domains)
		fmt.Fprintf(os.Stderr, "xhelix-dnspoison: loaded %d known-bad entries from %s\n",
			len(domains), *knownBadFile)
	}

	logger, closer, err := openLogger(*logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xhelix-dnspoison: log open:", err)
		os.Exit(2)
	}
	if closer != nil {
		defer closer.Close()
	}

	s, err := dnspoison.New(dnspoison.Config{
		UDPAddr:        *udpAddr,
		TCPAddr:        *tcpAddr,
		Upstream:       *upstream,
		SinkIP:         ip,
		Classifier:     cl,
		Logger:         logger,
		LogPassthrough: *logPass,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "xhelix-dnspoison: new:", err)
		os.Exit(2)
	}
	if err := s.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "xhelix-dnspoison: start:", err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "xhelix-dnspoison: listening UDP %s\n", s.UDPAddr().String())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	s.Stop()
}

func openLogger(logPath string) (dnspoison.Logger, io.Closer, error) {
	if fdStr := os.Getenv("XHELIX_DNSPOISON_LOG_FD"); fdStr != "" {
		fd, err := strconv.Atoi(fdStr)
		if err != nil {
			return nil, nil, fmt.Errorf("bad XHELIX_DNSPOISON_LOG_FD: %w", err)
		}
		f := os.NewFile(uintptr(fd), fmt.Sprintf("dnspoison-log-fd-%d", fd))
		if f == nil {
			return nil, nil, fmt.Errorf("could not open fd %d", fd)
		}
		return dnspoison.NewJSONLLogger(f), f, nil
	}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, err
		}
		return dnspoison.NewJSONLLogger(f), f, nil
	}
	return dnspoison.NewJSONLLogger(os.Stderr), nil, nil
}

func readDomainList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}
