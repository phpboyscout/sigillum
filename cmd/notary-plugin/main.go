// Command notary-plugin is spike code: a plugin that serves gRPC only to a host
// that launched it with a per-run token.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"spike/noisecreds"
	"spike/pb"
	"spike/pipeconn"
)

type server struct{ pb.UnimplementedPluginServer }

func (server) Describe(context.Context, *pb.DescribeRequest) (*pb.CommandTree, error) {
	return &pb.CommandTree{ProtocolVersion: "1", Commands: []*pb.Command{
		{Use: "notary serve", Short: "Run the notary service", Flags: []string{"--once"}},
		{Use: "notary review", Short: "Review one candidate", Flags: []string{"--commit"}},
	}}, nil
}

func (server) Run(req *pb.RunRequest, stream grpc.ServerStreamingServer[pb.Event]) error {
	_ = stream.Send(&pb.Event{Kind: &pb.Event_Log{Log: fmt.Sprintf("running %q args=%v config=%s secret-bytes=%d", req.Command, req.Args, req.ConfigJson, len(req.Secret))}})
	for i := int32(25); i <= 100; i += 25 {
		if err := stream.Context().Err(); err != nil {
			fmt.Fprintln(os.Stderr, "notary-plugin: run cancelled by host:", err)
			return err
		}
		_ = stream.Send(&pb.Event{Kind: &pb.Event_Progress{Progress: i}})
		time.Sleep(20 * time.Millisecond)
	}
	return stream.Send(&pb.Event{Kind: &pb.Event_Result{Result: "ok"}})
}

func main() {
	// The token arrives as the first line on stdin, never in the environment,
	// which other processes of the same user can read from /proc.
	stdin := bufio.NewReader(os.Stdin)
	var token []byte
	var err error
	if os.Getenv("SPIKE_PLUGIN_TRANSPORT") != "" {
		line, rerr := stdin.ReadString('\n')
		if rerr == nil {
			token, err = hex.DecodeString(strings.TrimSpace(line))
		}
	}
	if len(token) != 32 || err != nil {
		fmt.Fprintln(os.Stderr, "notary-plugin: this is a sigillum plugin; run it through sigillum")
		os.Exit(2)
	}

	var lis net.Listener
	switch t := os.Getenv("SPIKE_PLUGIN_TRANSPORT"); t {
	case "unix":
		path := os.Getenv("SPIKE_PLUGIN_SOCKET")
		lis, err = net.Listen("unix", path)
		if err == nil {
			fmt.Printf("1|unix|%s\n", path)
		}
	case "tcp":
		lis, err = net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			fmt.Printf("1|tcp|%s\n", lis.Addr())
		}
	case "stdio":
		// A stdio plugin has exactly one connection: when it closes, including after
		// a failed handshake, the plugin is done.
		lis = pipeconn.NewListener(&pipeconn.Conn{Reader: stdin, Writer: os.Stdout, Closer: func() error {
			os.Stdout.Close()
			os.Exit(3)
			return nil
		}})
	default:
		err = fmt.Errorf("unknown transport %q", t)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "notary-plugin:", err)
		os.Exit(1)
	}
	creds := noisecreds.New(token)
	if os.Getenv("SPIKE_INSECURE") != "" { // control run only: proves the tap would see plaintext
		creds = insecure.NewCredentials()
	}
	if t := os.Getenv("SPIKE_PLUGIN_TRANSPORT"); (t == "unix" || t == "tcp") && os.Getenv("SPIKE_NO_WATCH") == "" {
		// The host holds our stdin open for as long as it lives; EOF means it has
		// gone, so we go too rather than listen on as an orphan.
		go func() {
			_, _ = io.Copy(io.Discard, stdin)
			fmt.Fprintln(os.Stderr, "notary-plugin: host gone, exiting")
			os.Exit(0)
		}()
	}
	if os.Getenv("SPIKE_ONE_CONN") != "" {
		lis = &oneConn{Listener: lis}
	}
	s := grpc.NewServer(grpc.Creds(creds), grpc.ConnectionTimeout(2*time.Second))
	pb.RegisterPluginServer(s, server{})
	_ = s.Serve(lis)
}

// oneConn accepts the first connection and closes the listener, so nothing else
// can connect for the rest of the plugin's life.
type oneConn struct {
	net.Listener
	taken bool
}

func (o *oneConn) Accept() (net.Conn, error) {
	if o.taken {
		select {}
	}
	c, err := o.Listener.Accept()
	if err == nil {
		o.taken = true
		o.Listener.Close()
	}
	return c, err
}
