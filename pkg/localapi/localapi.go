// Package localapi is the local-socket interface xhelix exposes
// for the my-net-gate sibling UI. JSON-over-Unix-socket (the
// stdlib has no gRPC; this keeps the daemon CGO-free and the
// surface trivially scriptable).
//
// Protocol: one request → one or many responses on the same conn.
//
//	[4 bytes BE length][JSON payload]   repeated
//
// The server side dispatches request method names to registered
// handlers. Two-way streaming is supported by handlers that keep
// emitting frames until the client closes the conn.
//
// Pure-Go, stdlib only. mTLS-over-Unix is overkill for an LSM-
// path local socket; the kernel-enforced 0700 directory and 0660
// socket mode + getsockopt(SO_PEERCRED) for client uid checks are
// the appropriate trust model.
//
// Auth: callers pass an OptionAllowUIDs list. The server rejects
// any client whose peer credentials don't match. PID is logged
// for forensics but not used for auth (PIDs can be spoofed via
// timing; UIDs cannot without root).
package localapi

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
)

// Server is the local-socket dispatcher.
type Server struct {
	path        string
	allowUIDs   map[uint32]struct{}
	mu          sync.RWMutex
	handlers    map[string]Handler
	streamers   map[string]Streamer
	listener    net.Listener
	stopped     chan struct{}
}

// Handler is a single-request → single-response method.
type Handler func(ctx context.Context, req json.RawMessage) (any, error)

// Streamer is a single-request → many-responses method. The
// handler writes onto `out` until either it's done (close the
// channel) or ctx is cancelled.
type Streamer func(ctx context.Context, req json.RawMessage, out chan<- any) error

// Option mutates the Server.
type Option func(*Server)

// OptionAllowUIDs adds uids to the accept-list. If never set, the
// server accepts only its own uid (the running daemon's).
func OptionAllowUIDs(uids ...uint32) Option {
	return func(s *Server) {
		for _, u := range uids {
			s.allowUIDs[u] = struct{}{}
		}
	}
}

// NewServer returns a Server bound to path. Must be Start()ed
// before it accepts connections.
func NewServer(path string, opts ...Option) *Server {
	s := &Server{
		path:      path,
		allowUIDs: map[uint32]struct{}{},
		handlers:  map[string]Handler{},
		streamers: map[string]Streamer{},
		stopped:   make(chan struct{}),
	}
	for _, o := range opts {
		o(s)
	}
	if len(s.allowUIDs) == 0 {
		s.allowUIDs[uint32(os.Geteuid())] = struct{}{}
	}
	return s
}

// RegisterHandler binds a method name to a unary handler.
func (s *Server) RegisterHandler(method string, h Handler) {
	s.mu.Lock()
	s.handlers[method] = h
	s.mu.Unlock()
}

// RegisterStreamer binds a method name to a streaming handler.
func (s *Server) RegisterStreamer(method string, h Streamer) {
	s.mu.Lock()
	s.streamers[method] = h
	s.mu.Unlock()
}

// Start binds the socket and begins accepting connections in a
// background goroutine. Returns immediately.
func (s *Server) Start(ctx context.Context) error {
	_ = os.Remove(s.path)
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("localapi: listen: %w", err)
	}
	if err := os.Chmod(s.path, 0o660); err != nil {
		_ = ln.Close()
		return fmt.Errorf("localapi: chmod: %w", err)
	}
	s.listener = ln
	go s.serve(ctx)
	return nil
}

// Stop closes the listener. Safe to call multiple times.
func (s *Server) Stop() error {
	select {
	case <-s.stopped:
		return nil
	default:
	}
	close(s.stopped)
	if s.listener != nil {
		_ = s.listener.Close()
	}
	_ = os.Remove(s.path)
	return nil
}

func (s *Server) serve(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopped:
				return
			default:
				return
			}
		}
		go s.handleConn(ctx, conn)
	}
}

// peerUID returns the effective uid of the peer of a Unix-socket
// connection via SO_PEERCRED. Returns (0,false) on non-Unix or
// missing peer credentials.
func peerUID(conn net.Conn) (uint32, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	f, err := uc.File()
	if err != nil {
		return 0, false
	}
	defer f.Close()
	cred, err := syscall.GetsockoptUcred(int(f.Fd()),
		syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return 0, false
	}
	return cred.Uid, true
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	uid, ok := peerUID(conn)
	if !ok {
		writeError(conn, "no_peer_creds")
		return
	}
	s.mu.RLock()
	_, allowed := s.allowUIDs[uid]
	s.mu.RUnlock()
	if !allowed {
		writeError(conn, "unauthorized_peer_uid")
		return
	}

	for {
		var req frame
		if err := readFrame(conn, &req); err != nil {
			return
		}
		s.dispatch(ctx, conn, req)
	}
}

// envelope is the unified wire format used in both directions.
//
//	Request:  {"method":"x", "params":<...>}
//	Response: {"method":"x", "data":<...>}            (unary)
//	Stream:   {"method":"x", "data":<...>}            (per item)
//	         {"method":"x", "end":true}              (terminator)
//	Error:    {"method":"x", "err":"..."}
type envelope struct {
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"` // request-side payload
	Data   any             `json:"data,omitempty"`   // response-side payload
	Err    string          `json:"err,omitempty"`
	End    bool            `json:"end,omitempty"`
}

// frame is the legacy name used by readFrame. Alias keeps the
// reader concise.
type frame = envelope

func (s *Server) dispatch(ctx context.Context, conn net.Conn, req frame) {
	s.mu.RLock()
	h := s.handlers[req.Method]
	st := s.streamers[req.Method]
	s.mu.RUnlock()

	switch {
	case h != nil:
		out, err := h(ctx, req.Params)
		if err != nil {
			writeFrame(conn, envelope{Method: req.Method, Err: err.Error()})
			return
		}
		writeFrame(conn, envelope{Method: req.Method, Data: out})
	case st != nil:
		ch := make(chan any, 16)
		streamCtx, cancel := context.WithCancel(ctx)
		// Run the streamer in a goroutine; all wire writes happen
		// from the dispatch goroutine so they can't interleave.
		errCh := make(chan error, 1)
		go func() {
			err := st(streamCtx, req.Params, ch)
			close(ch)
			errCh <- err
		}()
		for v := range ch {
			if err := writeFrame(conn, envelope{Method: req.Method, Data: v}); err != nil {
				cancel()
				for range ch {
				}
				<-errCh
				return
			}
		}
		streamErr := <-errCh
		if streamErr != nil {
			writeFrame(conn, envelope{Method: req.Method, Err: streamErr.Error(), End: true})
		} else {
			writeFrame(conn, envelope{Method: req.Method, End: true})
		}
		cancel()
	default:
		writeFrame(conn, envelope{Method: req.Method, Err: "unknown_method"})
	}
}

// ── wire helpers ──────────────────────────────────────────────

func readFrame(r io.Reader, f *frame) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > 16<<20 {
		return errors.New("localapi: frame too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, f)
}

func writeFrame(w io.Writer, e envelope) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func writeError(w io.Writer, msg string) {
	_ = writeFrame(w, envelope{Err: msg})
}

// ── Client ────────────────────────────────────────────────────

// Client is the my-net-gate-side helper for talking to the
// daemon's LocalAPI.
type Client struct {
	conn net.Conn
}

// Dial connects to the daemon's local socket.
func Dial(path string) (*Client, error) {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	return &Client{conn: c}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Call issues a unary request and decodes the response into out
// (out may be nil to discard the payload).
func (c *Client) Call(method string, params any, out any) error {
	pb, err := json.Marshal(params)
	if err != nil {
		return err
	}
	if err := writeFrame(c.conn, envelopeFrame(method, pb)); err != nil {
		return err
	}
	var resp envelope
	if err := readResponse(c.conn, &resp); err != nil {
		return err
	}
	if resp.Err != "" {
		return errors.New(resp.Err)
	}
	if out == nil {
		return nil
	}
	rb, _ := json.Marshal(resp.Data)
	return json.Unmarshal(rb, out)
}

// Stream issues a streaming request; emit is called for each
// inbound frame's Data. Returns when the server signals End.
func (c *Client) Stream(ctx context.Context, method string, params any, emit func(json.RawMessage) error) error {
	pb, err := json.Marshal(params)
	if err != nil {
		return err
	}
	if err := writeFrame(c.conn, envelopeFrame(method, pb)); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var resp envelope
		if err := readResponse(c.conn, &resp); err != nil {
			return err
		}
		if resp.Err != "" {
			return errors.New(resp.Err)
		}
		if resp.End {
			return nil
		}
		if resp.Data != nil && emit != nil {
			rb, _ := json.Marshal(resp.Data)
			if err := emit(rb); err != nil {
				return err
			}
		}
	}
}

// envelopeFrame builds a request envelope.
func envelopeFrame(method string, params json.RawMessage) envelope {
	return envelope{Method: method, Params: params}
}

// readResponse decodes one envelope from the conn.
func readResponse(r io.Reader, e *envelope) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > 16<<20 {
		return errors.New("localapi: response too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, e)
}
