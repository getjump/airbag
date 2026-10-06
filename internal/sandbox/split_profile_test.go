package sandbox

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/getjump/airbag/internal/session"
)

func TestSplitProfilesKeepControlAndWorkspaceSeparate(t *testing.T) {
	t.Setenv("AIRBAG_HOME", t.TempDir())
	s, err := session.Create(session.Meta{Workspace: t.TempDir(), Home: t.TempDir(), Clone: true, Launcher: "codex-yolo-split"})
	if err != nil {
		t.Fatal(err)
	}
	base, err := macProfile(s, 51234, filepath.Join(s.Dir, "tmp"), filepath.Join(s.Dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	in := splitProfileIn{Control: filepath.Join(s.Dir, "control"), Tmp: filepath.Join(s.Dir, "control/tmp"), Cache: filepath.Join(s.Dir, "control/cache"), Socket: filepath.Join(s.Dir, "control/exec.sock"), RPC: filepath.Join(s.Dir, "control/rpc.sock")}
	worker, coordinator := splitProfiles(s, base, in)
	if !slices.Contains(worker.NoRead, follow(in.Control)) || !slices.Contains(worker.NoWrite, follow(in.Control)) {
		t.Fatal("worker can access control state")
	}
	for _, path := range []string{s.Workspace, s.CloneDir(), s.AgentStateDir()} {
		if !slices.Contains(coordinator.NoRead, follow(path)) || !slices.Contains(coordinator.NoWrite, follow(path)) {
			t.Fatalf("coordinator lacks denial for %s", path)
		}
		if slices.Contains(coordinator.Write, follow(path)) {
			t.Fatalf("coordinator writes %s", path)
		}
	}
	if !slices.Equal(coordinator.Ports, base.Ports) || !slices.Equal(coordinator.Sockets, []string{follow(in.Socket), follow(in.RPC)}) {
		t.Fatal("coordinator widened network boundary")
	}
}
