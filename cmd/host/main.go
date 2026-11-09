// Command host is spike code standing in for sigillum: it launches the plugin,
// connects over the chosen transport, and runs the positive and negative checks.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"spike/noisecreds"
	"spike/pb"
	"spike/pipeconn"
)

type launched struct {
	keep io.Closer
	cmd  *exec.Cmd
	dial func(context.Context, string) (net.Conn, error)
	addr string
}

func launch(plugin, transport string, token []byte, sockDir string) (*launched, error) {
	cmd := exec.Command(plugin)
	cmd.Env = []string{
		"SPIKE_PLUGIN_TRANSPORT=" + transport,
		"SPIKE_INSECURE=" + os.Getenv("SPIKE_INSECURE"),
		"SPIKE_NO_WATCH=" + os.Getenv("SPIKE_NO_WATCH"),
		"SPIKE_ONE_CONN=" + os.Getenv("SPIKE_ONE_CONN"),
	}
	cmd.Stderr = os.Stderr
	l := &launched{cmd: cmd}
	switch transport {
	case "unix", "tcp":
		if transport == "unix" {
			cmd.Env = append(cmd.Env, "SPIKE_PLUGIN_SOCKET="+filepath.Join(sockDir, "plugin.sock"))
		}
		out, _ := cmd.StdoutPipe()
		in, _ := cmd.StdinPipe()
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		fmt.Fprintln(in, hex.EncodeToString(token)) // stdin stays open: closing it tells the plugin we are gone
		l.keep = in
		line, err := bufio.NewReader(out).ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading handshake line: %w", err)
		}
		parts := strings.Split(strings.TrimSpace(line), "|")
		network, address := parts[1], parts[2]
		l.addr = network + ":" + address
		l.dial = func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		}
	case "stdio":
		in, _ := cmd.StdinPipe()
		out, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		fmt.Fprintln(in, hex.EncodeToString(token))
		pc := &pipeconn.Conn{Reader: out, Writer: in, Closer: in.Close}
		l.addr = "stdio"
		used := false
		l.dial = func(context.Context, string) (net.Conn, error) {
			if used {
				return nil, io.EOF
			}
			used = true
			return pc, nil
		}
	}
	return l, nil
}

type tapConn struct {
	net.Conn
	w io.Writer
}

func (t tapConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	t.w.Write(p[:n])
	return n, err
}
func (t tapConn) Write(p []byte) (int, error) { t.w.Write(p); return t.Conn.Write(p) }

func client(l *launched, token []byte) (pb.PluginClient, *grpc.ClientConn, error) {
	dial := l.dial
	if path := os.Getenv("SPIKE_TAP"); path != "" {
		f, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		dial = func(ctx context.Context, s string) (net.Conn, error) {
			c, err := l.dial(ctx, s)
			if err != nil {
				return nil, err
			}
			return tapConn{Conn: c, w: f}, nil
		}
	}
	cc, err := grpc.NewClient("passthrough:///plugin",
		grpc.WithContextDialer(dial),
		grpc.WithTransportCredentials(hostCreds(token)))
	if err != nil {
		return nil, nil, err
	}
	return pb.NewPluginClient(cc), cc, nil
}

func hostCreds(token []byte) credentials.TransportCredentials {
	if os.Getenv("SPIKE_INSECURE") != "" {
		return insecure.NewCredentials()
	}
	return noisecreds.New(token)
}

func newToken() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

func main() {
	plugin := flag.String("plugin", "./notary-plugin", "plugin executable")
	transport := flag.String("transport", "unix", "unix, tcp or stdio")
	flag.Parse()

	sockDir, _ := os.MkdirTemp("", "sigillum-plugin-")
	_ = os.Chmod(sockDir, 0o700)
	defer os.RemoveAll(sockDir)

	token := newToken()
	t0 := time.Now()
	l, err := launch(*plugin, *transport, token, sockDir)
	if err != nil {
		fmt.Println("FAIL launch:", err)
		os.Exit(1)
	}
	defer l.cmd.Process.Kill()
	c, cc, err := client(l, token)
	if err != nil {
		fmt.Println("FAIL client:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if os.Getenv("SPIKE_SLOW") != "" {
		time.Sleep(5 * time.Second)
	}
	tree, err := c.Describe(ctx, &pb.DescribeRequest{})
	if err != nil {
		fmt.Println("FAIL describe:", err)
		os.Exit(1)
	}
	fmt.Printf("[%s] describe ok in %s: protocol %s, %d commands:", l.addr, time.Since(t0).Round(time.Millisecond), tree.ProtocolVersion, len(tree.Commands))
	for _, cmd := range tree.Commands {
		fmt.Printf(" %q", cmd.Use)
	}
	fmt.Println()

	big := strings.Repeat("x", 200_000)
	stream, err := c.Run(ctx, &pb.RunRequest{Command: "notary review", Args: []string{"--commit", "abc123"},
		ConfigJson: []byte(`{"arbiter":{"mode":"strict"},"pad":"` + big + `"}`), Secret: []byte("s3cr3t-session-token")})
	if err != nil {
		fmt.Println("FAIL run:", err)
		os.Exit(1)
	}
	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("FAIL stream:", err)
			os.Exit(1)
		}
		switch k := ev.Kind.(type) {
		case *pb.Event_Log:
			fmt.Printf("[%s]   log: %.110s...\n", l.addr, k.Log)
		case *pb.Event_Progress:
			fmt.Printf("[%s]   progress %d%%\n", l.addr, k.Progress)
		case *pb.Event_Result:
			fmt.Printf("[%s]   result %s\n", l.addr, k.Result)
		}
	}
	cctx, ccancel := context.WithCancel(context.Background())
	st2, _ := c.Run(cctx, &pb.RunRequest{Command: "notary serve"})
	ev, _ := st2.Recv()
	ccancel()
	extra := 0
	for {
		if _, err = st2.Recv(); err != nil {
			break
		}
		extra++
	}
	time.Sleep(100 * time.Millisecond)
	fmt.Printf("[%s] cancel after first event (%T): %d buffered events, then %v\n", l.addr, ev.GetKind(), extra, err)

	if l.addr != "stdio" {
		// A second, plain gRPC client on the same socket or port, with no token.
		raw, _ := grpc.NewClient("passthrough:///plugin", grpc.WithContextDialer(l.dial),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
		t1 := time.Now()
		_, err := pb.NewPluginClient(raw).Describe(rctx, &pb.DescribeRequest{})
		rcancel()
		raw.Close()
		fmt.Printf("[%s] plain gRPC client without token: %v (after %s)\n", l.addr, err, time.Since(t1).Round(time.Millisecond))
	}
	cc.Close()
	l.cmd.Process.Kill()
	l.cmd.Wait()

	// Negative: a second plugin, connected to with the wrong token.
	_ = os.MkdirAll(sockDir+"/neg", 0o700)
	l2, err := launch(*plugin, *transport, newToken(), sockDir+"/neg")
	if err != nil {
		fmt.Println("neg launch:", err)
	} else {
		c2, cc2, _ := client(l2, newToken())
		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		_, err = c2.Describe(ctx2, &pb.DescribeRequest{})
		cancel2()
		if err == nil {
			fmt.Printf("[%s] FAIL: wrong token was accepted\n", l.addr)
		} else {
			fmt.Printf("[%s] wrong token refused: %v\n", l.addr, err)
		}
		cc2.Close()
		l2.cmd.Process.Kill()
		l2.cmd.Wait()
	}
}
