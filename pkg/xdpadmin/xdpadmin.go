// Package xdpadmin manages the runtime drop-set used by the XDP
// program in sensors/ebpf.
//
// The admin path lets userspace add/remove confirmed-bad IPs from
// the kernel-side drop set without touching iptables/nftables. When
// xhelix's eBPF object is loaded, this package opens the pinned
// xh_drop_set map and provides a small admin API for it.
//
// The admin is a no-op when the map is not pinned (e.g., on hosts
// where xhelix runs without root or without an eBPF backend).
package xdpadmin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
)

// Admin is the API used by the daemon and xhelixctl.
type Admin struct {
	mu      sync.Mutex
	pinPath string
	dropMap *ebpf.Map
}

// New returns an Admin. pinPath defaults to /sys/fs/bpf/xhelix/drop_set
// which is where the eBPF backend pins the map at Start.
func New(pinPath string) *Admin {
	if pinPath == "" {
		pinPath = "/sys/fs/bpf/xhelix/drop_set"
	}
	return &Admin{pinPath: pinPath}
}

// AttachMap accepts a live map handle so the daemon can wire its
// pinned reference straight in. Pass nil to detach.
func (a *Admin) AttachMap(m *ebpf.Map) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dropMap = m
}

// Add inserts ip into the drop set. Returns an error if the map is
// not attached or the IP is not v4 (v6 deferred).
func (a *Admin) Add(ip net.IP) error {
	a.mu.Lock()
	m := a.dropMap
	a.mu.Unlock()
	if m == nil {
		return errors.New("xdpadmin: drop map not attached")
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("xdpadmin: IPv6 not supported in v0.x: %s", ip)
	}
	key := binary.BigEndian.Uint32(v4)
	val := uint8(1)
	return m.Update(key, val, ebpf.UpdateAny)
}

// AddCIDR inserts every /32 in the CIDR. For privacy-respecting
// performance reasons we cap expansion at 65536 hosts (a /16).
func (a *Admin) AddCIDR(cidr *net.IPNet) error {
	if cidr == nil {
		return errors.New("xdpadmin: nil CIDR")
	}
	ones, bits := cidr.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("xdpadmin: only IPv4 CIDRs supported")
	}
	if ones < 16 {
		return fmt.Errorf("xdpadmin: refusing to expand %s — too wide", cidr)
	}
	for ip := cidr.IP.Mask(cidr.Mask); cidr.Contains(ip); incIP(ip) {
		if err := a.Add(append(net.IP{}, ip...)); err != nil {
			return err
		}
	}
	return nil
}

// Remove deletes ip from the drop set.
func (a *Admin) Remove(ip net.IP) error {
	a.mu.Lock()
	m := a.dropMap
	a.mu.Unlock()
	if m == nil {
		return errors.New("xdpadmin: drop map not attached")
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("xdpadmin: IPv6 not supported")
	}
	key := binary.BigEndian.Uint32(v4)
	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// List returns every IP currently in the drop set.
func (a *Admin) List() ([]net.IP, error) {
	a.mu.Lock()
	m := a.dropMap
	a.mu.Unlock()
	if m == nil {
		return nil, errors.New("xdpadmin: drop map not attached")
	}
	var out []net.IP
	var key uint32
	var val uint8
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, key)
		out = append(out, ip)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Clear empties the drop set.
func (a *Admin) Clear() error {
	ips, err := a.List()
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if err := a.Remove(ip); err != nil {
			return err
		}
	}
	return nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}
