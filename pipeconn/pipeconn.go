// Package pipeconn is spike code: a net.Conn over a reader/writer pair, and a
// listener that hands it out once, so gRPC can run over stdin/stdout.
package pipeconn

import (
	"io"
	"net"
	"sync"
	"time"
)

type addr struct{}

func (addr) Network() string { return "pipe" }
func (addr) String() string  { return "stdio" }

type Conn struct {
	io.Reader
	io.Writer
	Closer func() error
}

func (c *Conn) Close() error {
	if c.Closer != nil {
		return c.Closer()
	}
	return nil
}
func (c *Conn) LocalAddr() net.Addr              { return addr{} }
func (c *Conn) RemoteAddr() net.Addr             { return addr{} }
func (c *Conn) SetDeadline(time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }

type Listener struct {
	once sync.Once
	conn net.Conn
	done chan struct{}
}

func NewListener(c net.Conn) *Listener { return &Listener{conn: c, done: make(chan struct{})} }

func (l *Listener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *Listener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}
func (l *Listener) Addr() net.Addr { return addr{} }
