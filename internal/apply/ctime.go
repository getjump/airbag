package apply

import (
	"time"

	"golang.org/x/sys/unix"
)

func ctime(st *unix.Stat_t) time.Time { return time.Unix(st.Ctim.Sec, st.Ctim.Nsec) }
