package steps_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

const mcpTimeout = 30 * time.Second

func registerMCPSteps(ctx *godog.ScenarioContext, w *world) {
	ctx.When(`^I browse the MCP tool catalogue$`, w.browseMCPCatalogue)
	ctx.Given(`^the CLI has the command behind the MCP tool "([^"]*)"$`, w.cliHasCommandBehindTool)
	ctx.When(`^I call the MCP tool "([^"]*)"$`, w.callMCPTool)
	ctx.When(`^I run mcp stream$`, w.runMCPStream)
	ctx.Then(`^the catalogue lists exactly these tools:$`, w.catalogueListsExactly)
	ctx.Then(`^the MCP call is refused as unavailable$`, w.mcpCallRefusedAsUnavailable)
}

// mcpSession is `sigillum mcp start` spoken to over stdio, one JSON-RPC
// message per line.
type mcpSession struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  *bufio.Scanner
	nextID int
}

type mcpResult struct {
	StructuredContent json.RawMessage `json:"structuredContent"`
	IsError           bool            `json:"isError"`
}

func (w *world) startMCP(ctx context.Context) (*mcpSession, error) {
	bin, err := sigillumBinary()
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, bin, "mcp", "start", "--ci")
	cmd.Dir = w.dir

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	lines := bufio.NewScanner(stdout)
	lines.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	s := &mcpSession{cmd: cmd, stdin: stdin, lines: lines}

	if _, err := s.request("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "sigillum-e2e", "version": "0"},
	}); err != nil {
		s.close()

		return nil, fmt.Errorf("initialize: %w", err)
	}

	if err := s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		s.close()

		return nil, err
	}

	return s, nil
}

func (s *mcpSession) send(msg map[string]any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = s.stdin.Write(append(b, '\n'))

	return err
}

// request sends one call and returns its result, skipping any notification
// the server interleaves.
func (s *mcpSession) request(method string, params any) (json.RawMessage, error) {
	s.nextID++
	id := s.nextID

	if err := s.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}

	for s.lines.Scan() {
		var reply struct {
			ID     *int            `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}

		if err := json.Unmarshal(s.lines.Bytes(), &reply); err != nil {
			return nil, fmt.Errorf("stdout carried a line that is not JSON-RPC: %q", s.lines.Text())
		}

		if reply.ID == nil || *reply.ID != id {
			continue
		}

		if len(reply.Error) > 0 {
			return nil, fmt.Errorf("%s: %s", method, reply.Error)
		}

		return reply.Result, nil
	}

	if err := s.lines.Err(); err != nil {
		return nil, err
	}

	return nil, errors.New("the server closed stdout before replying")
}

func (s *mcpSession) callTool(name string, args map[string]any) (mcpResult, error) {
	raw, err := s.request("tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return mcpResult{}, err
	}

	var r mcpResult

	return r, json.Unmarshal(raw, &r)
}

func (s *mcpSession) close() {
	_ = s.stdin.Close()
	_ = s.cmd.Wait()
}

func (w *world) browseMCPCatalogue() error {
	ctx, cancel := context.WithTimeout(context.Background(), mcpTimeout)
	defer cancel()

	s, err := w.startMCP(ctx)
	if err != nil {
		return err
	}
	defer s.close()

	w.mcpTools = nil
	cursor := ""

	for {
		args := map[string]any{"limit": 20}
		if cursor != "" {
			args["cursor"] = cursor
		}

		r, err := s.callTool("search_tools", args)
		if err != nil {
			return err
		}

		if r.IsError {
			return fmt.Errorf("search_tools failed: %s", r.StructuredContent)
		}

		var page struct {
			Operations []struct {
				Name string `json:"name"`
			} `json:"operations"`
			NextCursor string `json:"nextCursor"`
		}

		if err := json.Unmarshal(r.StructuredContent, &page); err != nil {
			return err
		}

		for _, op := range page.Operations {
			w.mcpTools = append(w.mcpTools, op.Name)
		}

		if page.NextCursor == "" {
			return nil
		}

		cursor = page.NextCursor
	}
}

func (w *world) callMCPTool(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), mcpTimeout)
	defer cancel()

	s, err := w.startMCP(ctx)
	if err != nil {
		return err
	}
	defer s.close()

	r, err := s.callTool("call_tool", map[string]any{"name": name, "arguments": map[string]any{}})
	if err != nil {
		return err
	}

	w.mcpCall = r

	return nil
}

func (w *world) catalogueListsExactly(table *godog.Table) error {
	want := make([]string, 0, len(table.Rows))
	for _, row := range table.Rows {
		want = append(want, row.Cells[0].Value)
	}

	got := slices.Clone(w.mcpTools)
	slices.Sort(want)
	slices.Sort(got)

	if !slices.Equal(got, want) {
		return fmt.Errorf("served tools differ from spec 0003 D2\n got: %s\nwant: %s",
			strings.Join(got, ", "), strings.Join(want, ", "))
	}

	return nil
}

func (w *world) mcpCallRefusedAsUnavailable() error {
	if !w.mcpCall.IsError {
		return fmt.Errorf("the call ran: %s", w.mcpCall.StructuredContent)
	}

	var body struct {
		Failure struct {
			Code string `json:"code"`
		} `json:"failure"`
	}

	if err := json.Unmarshal(w.mcpCall.StructuredContent, &body); err != nil {
		return err
	}

	if body.Failure.Code != "unavailable" {
		return fmt.Errorf("refused with %q, want %q: %s", body.Failure.Code, "unavailable", w.mcpCall.StructuredContent)
	}

	return nil
}

// runMCPStream is bounded, because a regression would leave it listening.
func (w *world) runMCPStream() error {
	ctx, cancel := context.WithTimeout(context.Background(), mcpTimeout)
	defer cancel()

	bin, err := sigillumBinary()
	if err != nil {
		return err
	}

	var stderr strings.Builder

	cmd := exec.CommandContext(ctx, bin, "mcp", "stream", "--ci", "--host", "127.0.0.1", "--port", "0")
	cmd.Dir = w.dir
	cmd.Stderr = &stderr

	w.exitErr = cmd.Run()
	w.stderr = stderr.String()

	if ctx.Err() != nil {
		return errors.New("mcp stream was still running at the timeout: it served instead of refusing")
	}

	return nil
}

// cliHasCommandBehindTool stops a misspelt tool name passing as withheld: an
// unknown tool also answers unavailable. Help on a misspelt path falls back to
// the parent's usage, so the usage line is what proves the command exists.
func (w *world) cliHasCommandBehindTool(tool string) error {
	name, ok := strings.CutPrefix(tool, "sigillum_")
	if !ok {
		return fmt.Errorf("tool %q does not start with sigillum_", tool)
	}

	path := strings.Split(name, "_")

	if err := w.run(append(slices.Clone(path), "--help", "--ci")...); err != nil {
		return err
	}

	if w.exitErr != nil {
		return fmt.Errorf("%s --help failed: %w\n%s", strings.Join(path, " "), w.exitErr, w.stderr)
	}

	want := "Usage:\n  sigillum " + strings.Join(path, " ") + " "
	if !strings.Contains(w.stdout, want) {
		return fmt.Errorf("no command %q behind tool %q; help printed:\n%s", strings.Join(path, " "), tool, w.stdout)
	}

	return nil
}
