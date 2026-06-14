//go:build linux

package dpi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/xhelix/xhelix/pkg/connstate"
	"github.com/xhelix/xhelix/pkg/dpi"
	"github.com/xhelix/xhelix/pkg/ja3"
)

func htons(h uint16) uint16 { return (h<<8)&0xff00 | h>>8 }

type impl struct {
	fd      int
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running atomic.Bool
}

func newImpl() impl { return impl{fd: -1} }

func (i *impl) start(parent context.Context, cfg Config, tab *connstate.Table) error {
	if tab == nil {
		return errors.New("dpi: nil conn-table")
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("dpi: AF_PACKET socket: %w (need CAP_NET_RAW?)", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	tv := unix.Timeval{Sec: 0, Usec: 250 * 1000}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	i.fd = fd
	ctx, cancel := context.WithCancel(parent)
	i.cancel = cancel
	i.running.Store(true)
	i.wg.Add(1)
	go i.readLoop(ctx, cfg, tab)
	return nil
}

func (i *impl) stop() error {
	if !i.running.Load() {
		return nil
	}
	i.running.Store(false)
	if i.cancel != nil {
		i.cancel()
	}
	if i.fd >= 0 {
		_ = unix.Close(i.fd)
		i.fd = -1
	}
	i.wg.Wait()
	return nil
}

func (i *impl) health() error {
	if !i.running.Load() {
		return errors.New("dpi: not running")
	}
	return nil
}

func (i *impl) readLoop(ctx context.Context, cfg Config, tab *connstate.Table) {
	defer i.wg.Done()
	buf := make([]byte, 2048)
	for ctx.Err() == nil && i.running.Load() {
		n, _, err := unix.Recvfrom(i.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		if n <= 0 {
			continue
		}
		processL3(buf[:n], cfg.MaxBytes, tab)
	}
}

func processL3(pkt []byte, maxParse int, tab *connstate.Table) {
	if len(pkt) < 1 {
		return
	}
	v := pkt[0] >> 4
	switch v {
	case 4:
		processV4(pkt, maxParse, tab)
	case 6:
		processV6(pkt, maxParse, tab)
	}
}

func processV4(pkt []byte, maxParse int, tab *connstate.Table) {
	if len(pkt) < 20 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return
	}
	if pkt[9] != 6 {
		return
	}
	srcIP, _ := netip.AddrFromSlice(pkt[12:16])
	dstIP, _ := netip.AddrFromSlice(pkt[16:20])
	tcp := pkt[ihl:]
	processTCP(tcp, srcIP, dstIP, maxParse, tab)
}

func processV6(pkt []byte, maxParse int, tab *connstate.Table) {
	if len(pkt) < 40 {
		return
	}
	if pkt[6] != 6 {
		return
	}
	srcIP, _ := netip.AddrFromSlice(pkt[8:24])
	dstIP, _ := netip.AddrFromSlice(pkt[24:40])
	tcp := pkt[40:]
	processTCP(tcp, srcIP, dstIP, maxParse, tab)
}

func processTCP(tcp []byte, srcIP, dstIP netip.Addr, maxParse int, tab *connstate.Table) {
	if len(tcp) < 20 {
		return
	}
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	if dstPort != 443 && srcPort != 443 {
		return
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || dataOff > len(tcp) {
		return
	}
	payload := tcp[dataOff:]
	if len(payload) < 6 {
		return
	}
	if payload[0] != 0x16 {
		return
	}
	if maxParse > 0 && len(payload) > maxParse {
		payload = payload[:maxParse]
	}
	// Parse the ClientHello once via ja3 to recover SNI and the
	// client-offered ALPN list (EO.5b). ja3 is heavier than the
	// SNI-only parser but operates on the same already-sliced bytes,
	// so there are no per-packet allocations beyond this one parse.
	var (
		sni  string
		alpn string
	)
	if fp, err := ja3.Parse(payload); err == nil {
		sni = fp.SNI
		alpn = alpnHint(fp.ALPN)
	}
	// Never regress SNI: if ja3 failed or yielded no SNI, fall back to
	// the original SNI-only parser.
	if sni == "" {
		if s, ok := dpi.ParseClientHelloSNI(payload); ok {
			sni = s
		}
	}
	if sni == "" && alpn == "" {
		return
	}
	if dstPort == 443 {
		tup := connstate.Tuple{
			Proto:   connstate.ProtoTCP,
			SrcPort: srcPort,
			DstAddr: dstIP,
			DstPort: dstPort,
		}
		if sni != "" {
			tab.AttachSNI(tup, sni)
		}
		if alpn != "" {
			tab.AttachALPN(tup, alpn)
		}
	}
	_ = srcIP // unused; kept for symmetry when we add reverse-direction parsing
}

// alpnHint reduces a client-offered ALPN list to a single coarse hint
// token: "grpc" if grpc is offered, else "h2" if HTTP/2 is offered,
// else "" (http/1.1 is too noisy to use as a label).
func alpnHint(offered []string) string {
	var hasH2 bool
	for _, p := range offered {
		switch p {
		case "grpc":
			return "grpc"
		case "h2", "h2c":
			hasH2 = true
		}
	}
	if hasH2 {
		return "h2"
	}
	return ""
}
