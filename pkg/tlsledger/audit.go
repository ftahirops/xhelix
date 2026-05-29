package tlsledger

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// FileAuditLogger writes one JSON line per access to an append-only
// file. Callers should open the file with O_APPEND|O_CREATE|O_WRONLY
// and 0600 perms.
type FileAuditLogger struct {
	mu sync.Mutex
	w  io.Writer
}

// NewFileAuditLogger wraps w. w is typically an *os.File opened
// O_APPEND|O_CREATE|O_WRONLY at /var/log/xhelix/tls-plaintext-access.log.
func NewFileAuditLogger(w io.Writer) *FileAuditLogger {
	return &FileAuditLogger{w: w}
}

// LogAccess implements AuditLogger. Format is one JSON line per access
// keyed by timestamp + remote IP + action + record ID + binary.
func (f *FileAuditLogger) LogAccess(remoteIP, action, recordID, binary string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.w == nil {
		return
	}
	// Hand-rolled to avoid encoding/json allocation for a hot path.
	fmt.Fprintf(f.w,
		`{"time":"%s","remote_ip":%q,"action":%q,"record_id":%q,"binary":%q}`+"\n",
		time.Now().UTC().Format(time.RFC3339Nano),
		remoteIP, action, recordID, binary,
	)
}
