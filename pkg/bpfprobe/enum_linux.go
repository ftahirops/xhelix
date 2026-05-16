//go:build linux

package bpfprobe

import (
	"encoding/hex"
	"syscall"
	"unsafe"
)

// BPF syscall command numbers (from linux/bpf.h)
const (
	bpfPROG_GET_NEXT_ID  = 11
	bpfPROG_GET_FD_BY_ID = 13
	bpfOBJ_GET_INFO_BY_FD = 15
)

// bpf_prog_info partial struct (only the fields we need).
// Layout is *not* stable across kernel versions for trailing
// fields, so we treat the buffer as a black-box and only read
// the documented head.
type bpfProgInfoCore struct {
	Type        uint32
	ID          uint32
	Tag         [8]byte
	JitedLen    uint32
	XlatedLen   uint32
	JitedAddr   uint64
	XlatedAddr  uint64
	LoadTime    uint64 // ns since boot
	CreatedUID  uint32
	NrMapIDs    uint32
	MapIDs      uint64
	Name        [16]byte
	IfIndex     uint32
	Gpl         uint32 // flag bits incl. gpl_compatible
}

// bpf_attr union for the three syscalls we use. We always
// zero-fill to the largest variant size.
type bpfAttr struct {
	pad [128]byte
}

// SnapshotNow enumerates every loaded eBPF program and returns
// the Snapshot. Requires CAP_BPF or CAP_SYS_ADMIN; non-root
// callers receive an empty Snapshot and no error.
func SnapshotNow() (Snapshot, error) {
	var snap Snapshot
	id := uint32(0)
	for {
		next, ok := getNextID(id)
		if !ok {
			break
		}
		fd, ok := getFDByID(next)
		if !ok {
			id = next
			continue
		}
		info, ok := getInfo(fd)
		_ = syscall.Close(fd)
		if !ok {
			id = next
			continue
		}
		info.ID = next
		info.TypeName = ProgTypeName(info.Type)
		snap.Progs = append(snap.Progs, info)
		id = next
	}
	return snap, nil
}

// getNextID returns the next-loaded program ID after id, or
// (0,false) if there isn't one (or we lack permission).
func getNextID(id uint32) (uint32, bool) {
	var attr bpfAttr
	// start_id is at offset 0 of the union variant.
	*(*uint32)(unsafe.Pointer(&attr.pad[0])) = id
	r1, _, errno := syscall.Syscall(sysBPF,
		uintptr(bpfPROG_GET_NEXT_ID),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, false
	}
	// next_id is written back at offset 4.
	_ = r1
	next := *(*uint32)(unsafe.Pointer(&attr.pad[4]))
	return next, true
}

// getFDByID returns the fd referring to program `id`.
func getFDByID(id uint32) (int, bool) {
	var attr bpfAttr
	*(*uint32)(unsafe.Pointer(&attr.pad[0])) = id
	r1, _, errno := syscall.Syscall(sysBPF,
		uintptr(bpfPROG_GET_FD_BY_ID),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, false
	}
	return int(r1), true
}

// getInfo populates a ProgInfo by issuing BPF_OBJ_GET_INFO_BY_FD.
func getInfo(fd int) (ProgInfo, bool) {
	var info bpfProgInfoCore
	var attr bpfAttr
	// bpf_attr.info: { bpf_fd, info_len, info }
	*(*uint32)(unsafe.Pointer(&attr.pad[0])) = uint32(fd)
	*(*uint32)(unsafe.Pointer(&attr.pad[4])) = uint32(unsafe.Sizeof(info))
	*(*uint64)(unsafe.Pointer(&attr.pad[8])) = uint64(uintptr(unsafe.Pointer(&info)))
	_, _, errno := syscall.Syscall(sysBPF,
		uintptr(bpfOBJ_GET_INFO_BY_FD),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr))
	if errno != 0 {
		return ProgInfo{}, false
	}
	return ProgInfo{
		Type:          info.Type,
		Tag:           hex.EncodeToString(info.Tag[:]),
		Name:          nullTermString(info.Name[:]),
		LoadTime:      info.LoadTime,
		CreatedByUID:  info.CreatedUID,
		GPLCompatible: info.Gpl != 0,
	}, true
}

func nullTermString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
