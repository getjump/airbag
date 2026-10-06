package sandbox

import (
	"github.com/getjump/airbag/internal/seatbelt"
	"github.com/getjump/airbag/internal/session"
)

type splitProfileIn struct{ Control, Tmp, Cache, Socket, RPC string }

func splitProfiles(s *session.Session, base seatbelt.Profile, in splitProfileIn) (worker, coordinator seatbelt.Profile) {
	worker = base
	worker.NoRead = append(append([]string{}, base.NoRead...), follow(in.Control))
	worker.NoWrite = append(append([]string{}, base.NoWrite...), follow(in.Control))
	coordinator = base
	coordinator.Tag += "-coordinator"
	coordinator.Write = []string{follow(in.Control), follow(in.Tmp), follow(in.Cache)}
	coordinator.WriteFiles = nil
	coordinator.Sockets = []string{follow(in.Socket), follow(in.RPC)}
	coordinator.NoRead = append(append([]string{}, base.NoRead...), follow(s.CloneDir()), follow(s.Workspace), follow(s.AgentStateDir()))
	coordinator.NoWrite = append(append([]string{}, base.NoWrite...), follow(s.CloneDir()), follow(s.Workspace), follow(s.AgentStateDir()))
	return worker, coordinator
}
