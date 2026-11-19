package webui

import (
	"os"
	"strings"
	"testing"
)

// TestAdminBulkConfirm: every bulk decision takes the two-step confirm
// (not only the destructive ones), and an armed bulk button is disarmed
// when the selection changes, so the second click applies only to the rows
// selected when it was armed. Static: there is no DOM to run the script in.
func TestAdminBulkConfirm(t *testing.T) {
	b, err := os.ReadFile("static/admin.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	_, run, ok := strings.Cut(src, "function bulkRun(reg, b) {")
	if !ok {
		t.Fatal("no bulkRun")
	}
	run, _, _ = strings.Cut(run, "\n  }\n")
	if strings.Contains(run, "acct-del") {
		t.Error("bulkRun confirms only some decisions")
	}
	for _, want := range []string{"if (!armed(b)) return;", "if (b.dataset.armed === '1' && b.dataset.sel !== sel) disarm(b);"} {
		if !strings.Contains(run, want) {
			t.Errorf("bulkRun lacks %q", want)
		}
	}
	if i, j := strings.Index(run, "if (!armed(b)) return;"), strings.Index(run, "run(b,"); i < 0 || j < i {
		t.Error("bulkRun posts before the confirm")
	}
	_, sync, _ := strings.Cut(src, "function bulkSync(reg) {")
	sync, _, _ = strings.Cut(sync, "\n  }\n")
	if !strings.Contains(sync, "bar.querySelectorAll('button[data-bulk-act]').forEach(disarm);") {
		t.Error("a selection change does not disarm the bulk buttons")
	}
}
