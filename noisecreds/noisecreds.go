// Package noisecreds is spike code: gRPC transport credentials that run a Noise
// NNpsk0 handshake keyed by a per-run token instead of TLS.
package noisecreds

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/flynn/noise"
	"google.golang.org/grpc/credentials"
)

var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

type creds struct{ token []byte }

func New(token []byte) credentials.TransportCredentials { return &creds{token: token} }

type authInfo struct{ credentials.CommonAuthInfo }

func (authInfo) AuthType() string { return "noise-nnpsk0" }

func (c *creds) handshake(conn net.Conn, initiator bool) (net.Conn, credentials.AuthInfo, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite, Pattern: noise.HandshakeNN, Initiator: initiator,
		PresharedKey: c.token, PresharedKeyPlacement: 0,
	})
	if err != nil {
		return nil, nil, err
	}
	var send, recv *noise.CipherState
	if initiator {
		msg, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			return nil, nil, err
		}
		if err := writeFrame(conn, msg); err != nil {
			return nil, nil, err
		}
		in, err := readFrame(conn)
		if err != nil {
			return nil, nil, err
		}
		_, cs1, cs2, err := hs.ReadMessage(nil, in)
		if err != nil {
			return nil, nil, fmt.Errorf("noise handshake: %w", err)
		}
		send, recv = cs1, cs2
	} else {
		// NNpsk0's first message is exactly an ephemeral key and an empty payload's
		// tag. Anything else is not our host, so refuse before reading further.
		var h [2]byte
		if _, err := io.ReadFull(conn, h[:]); err != nil {
			return nil, nil, err
		}
		if n := binary.BigEndian.Uint16(h[:]); n != firstMsgLen {
			return nil, nil, fmt.Errorf("noise handshake: unexpected first frame of %d bytes", n)
		}
		in := make([]byte, firstMsgLen)
		if _, err := io.ReadFull(conn, in); err != nil {
			return nil, nil, err
		}
		if _, _, _, err := hs.ReadMessage(nil, in); err != nil {
			return nil, nil, fmt.Errorf("noise handshake: %w", err)
		}
		msg, cs1, cs2, err := hs.WriteMessage(nil, nil)
		if err != nil {
			return nil, nil, err
		}
		if err := writeFrame(conn, msg); err != nil {
			return nil, nil, err
		}
		send, recv = cs2, cs1
	}
	ai := authInfo{credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}}
	return &conn2{Conn: conn, send: send, recv: recv}, ai, nil
}

func (c *creds) ClientHandshake(ctx context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// A pipe has no deadlines, so the context is the only way out of a stalled handshake.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	return c.handshake(conn, true)
}
func (c *creds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c.handshake(conn, false)
}
func (c *creds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "noise-nnpsk0"}
}
func (c *creds) Clone() credentials.TransportCredentials { return &creds{token: c.token} }
func (c *creds) OverrideServerName(string) error         { return nil }

const (
	maxPlain    = noise.MaxMsgLen - 16
	firstMsgLen = 32 + 16
)

func writeFrame(w io.Writer, b []byte) error {
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(b)))
	if _, err := w.Write(append(h[:], b...)); err != nil {
		return err
	}
	return nil
}

func readFrame(r io.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(h[:]))
	_, err := io.ReadFull(r, b)
	return b, err
}

type conn2 struct {
	net.Conn
	send, recv *noise.CipherState
	wmu, rmu   sync.Mutex
	pending    []byte
}

func (c *conn2) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	n := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlain {
			chunk = p[:maxPlain]
		}
		ct, err := c.send.Encrypt(nil, nil, chunk)
		if err != nil {
			return n, err
		}
		if err := writeFrame(c.Conn, ct); err != nil {
			return n, err
		}
		n += len(chunk)
		p = p[len(chunk):]
	}
	return n, nil
}

func (c *conn2) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		ct, err := readFrame(c.Conn)
		if err != nil {
			return 0, err
		}
		pt, err := c.recv.Decrypt(nil, nil, ct)
		if err != nil {
			return 0, errors.Join(errors.New("noise: decrypt"), err)
		}
		c.pending = pt
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
