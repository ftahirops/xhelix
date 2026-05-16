// xhelix-bridge is the Chrome / Firefox native-messaging host
// that forwards tab + navigation events from the browser
// extension into the xhelix daemon's LocalAPI.
//
// Browser wire format: stdin/stdout, length-prefixed JSON
// (4-byte little-endian length + JSON bytes). Spec:
// https://developer.chrome.com/docs/apps/nativeMessaging/
//
// We translate each incoming message into a LocalAPI Call to
// `browser.event`. The daemon's handler is responsible for
// attaching the (tab, URL, referrer) metadata to the next
// outbound connect by the same pid.
//
// Install path (per Chrome's docs):
//   /etc/opt/chrome/native-messaging-hosts/io.xhelix.bridge.json
//
// Manifest:
//   {
//     "name": "io.xhelix.bridge",
//     "description": "xhelix browser bridge",
//     "path": "/usr/local/libexec/xhelix-bridge",
//     "type": "stdio",
//     "allowed_origins": ["chrome-extension://<EXT_ID>/"]
//   }
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/xhelix/xhelix/pkg/localapi"
)

func main() {
	socketPath := flag.String("socket", "/run/xhelix.sock", "xhelix LocalAPI socket")
	flag.Parse()

	// Log to stderr so it shows in browser DevTools native-host
	// diagnostics. Anything on stdout would corrupt the
	// length-prefixed wire format.
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	c, err := localapi.Dial(*socketPath)
	if err != nil {
		log.Printf("xhelix-bridge: dial %s: %v", *socketPath, err)
		os.Exit(1)
	}
	defer c.Close()

	for {
		msg, err := readNativeMessage(os.Stdin)
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Printf("xhelix-bridge: read: %v", err)
			return
		}
		var resp any
		if err := c.Call("browser.event", msg, &resp); err != nil {
			log.Printf("xhelix-bridge: forward: %v", err)
			// Send a small ack-with-error frame back to the
			// extension so it can decide to reconnect.
			_ = writeNativeMessage(os.Stdout, map[string]any{
				"ok": false, "err": err.Error(),
			})
			continue
		}
		// Browser side doesn't need every ack; only respond when
		// the daemon returned non-nil.
		if resp != nil {
			_ = writeNativeMessage(os.Stdout, resp)
		}
	}
}

// readNativeMessage reads one length-prefixed JSON object.
// Chrome uses native byte order; we read little-endian (the only
// supported arch in 2026 is little-endian).
func readNativeMessage(r io.Reader) (json.RawMessage, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n > 1<<22 { // 4 MB cap per Chrome's docs
		return nil, fmt.Errorf("xhelix-bridge: message too large: %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return json.RawMessage(buf), nil
}

// writeNativeMessage writes one length-prefixed JSON object.
func writeNativeMessage(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(b)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
