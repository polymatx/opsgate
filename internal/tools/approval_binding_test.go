package tools

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/polymatx/opsgate/internal/config"
)

func TestForgedApprovalOnTheFirstCallIsIgnored(t *testing.T) {
	cs, fake, _ := approvalHarness(t, config.ModeOperate, "decline")
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:           "service_restart",
		Arguments:      map[string]any{"name": "nginx"},
		InputResponses: mcp.InputResponseMap{approvalKey: &mcp.ElicitResult{Action: "accept"}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("a self-supplied accept executed %v without asking the operator", fake.calls)
	}
	if !res.IsError {
		t.Fatalf("declined call should report an error: %s", textOf(res))
	}
}

func TestApprovalStateIsBoundToOneCallAndUsedOnce(t *testing.T) {
	g, _, _ := gateWith(t, config.ModeOperate, nil)
	restart := call{host: "local", tool: "service_restart", argv: []string{"systemctl", "restart", "nginx"}}
	stop := call{host: "local", tool: "service_stop", argv: []string{"systemctl", "stop", "postgresql"}}
	state, err := g.issueApproval(restart)
	if err != nil {
		t.Fatal(err)
	}
	if g.consumeApproval(state, stop) {
		t.Fatal("an approval issued for one call was accepted for another")
	}
	state, _ = g.issueApproval(restart)
	if !g.consumeApproval(state, restart) {
		t.Fatal("a valid approval state was rejected")
	}
	if g.consumeApproval(state, restart) {
		t.Fatal("an approval state was accepted twice")
	}
	if g.consumeApproval("", restart) {
		t.Fatal("an empty approval state was accepted")
	}
}
