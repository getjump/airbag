package effects_test

// These are storage diagnostics, not production backends. Every variant waits
// for its synchronous commit before returning. Run on a non-volatile disk to
// measure durability cost; an overlay mounted fsync=volatile only measures CPU.

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/effects"
)

type diagnosticStore interface {
	add([]effects.Effect) error
	close() error
	read() ([]effects.Effect, error)
}

type sqliteAudit struct {
	log  *effects.Log
	path string
}

func (s *sqliteAudit) add(es []effects.Effect) error   { return s.log.AddBatchChecked(es) }
func (s *sqliteAudit) close() error                    { return s.log.Close() }
func (s *sqliteAudit) read() ([]effects.Effect, error) { return effects.Read(s.path) }

// The flat SQLite variant isolates schema work from the engine/driver. It does
// not implement the production query schema or append-only triggers.
type flatSQLite struct {
	db   *sql.DB
	stmt *sql.Stmt
	path string
}

func openFlatSQLite(path string) (*flatSQLite, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE events (id INTEGER PRIMARY KEY, data TEXT NOT NULL)`); err != nil {
		db.Close()
		return nil, err
	}
	stmt, err := db.Prepare(`INSERT INTO events (data) VALUES (?)`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &flatSQLite{db: db, stmt: stmt, path: path}, nil
}

func (s *flatSQLite) add(es []effects.Effect) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt := tx.Stmt(s.stmt)
	defer stmt.Close()
	for _, e := range es {
		data, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := stmt.Exec(string(data)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *flatSQLite) close() error {
	if err := s.stmt.Close(); err != nil {
		s.db.Close()
		return err
	}
	return s.db.Close()
}

func (s *flatSQLite) read() ([]effects.Effect, error) {
	db, err := sql.Open("sqlite", "file:"+s.path+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT data FROM events ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []effects.Effect
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var e effects.Effect
		if err := json.Unmarshal([]byte(data), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// One checksummed frame contains one commit group. Sequence/count are covered
// by CRC too. This is a diagnostic format: no crash recovery, index, rotation,
// tamper evidence, concurrent writer support, or production reader is provided.
const frameMagic = uint32(0x31424741)
const frameHeaderSize = 24

type appendJournal struct {
	f    *os.File
	path string
	next uint64
}

func openAppendJournal(path string) (*appendJournal, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		f.Close()
		return nil, err
	}
	return &appendJournal{f: f, path: path}, nil
}

func (s *appendJournal) add(es []effects.Effect) error {
	data, err := json.Marshal(es)
	if err != nil {
		return err
	}
	frame := make([]byte, frameHeaderSize+len(data))
	binary.LittleEndian.PutUint32(frame[0:4], frameMagic)
	binary.LittleEndian.PutUint32(frame[4:8], uint32(len(data)))
	binary.LittleEndian.PutUint64(frame[8:16], s.next)
	binary.LittleEndian.PutUint32(frame[16:20], uint32(len(es)))
	copy(frame[frameHeaderSize:], data)
	checksum := crc32.NewIEEE()
	checksum.Write(frame[8:20])
	checksum.Write(data)
	binary.LittleEndian.PutUint32(frame[20:24], checksum.Sum32())
	for len(frame) > 0 {
		n, err := s.f.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	if err := s.f.Sync(); err != nil {
		return err
	}
	s.next += uint64(len(es))
	return nil
}

func (s *appendJournal) close() error { return s.f.Close() }

func (s *appendJournal) read() ([]effects.Effect, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []effects.Effect
	var header [frameHeaderSize]byte
	for {
		if _, err := io.ReadFull(f, header[:]); err != nil {
			if err == io.EOF {
				return out, nil
			}
			return nil, err
		}
		n := binary.LittleEndian.Uint32(header[4:8])
		if binary.LittleEndian.Uint32(header[0:4]) != frameMagic || n > 8<<20 || binary.LittleEndian.Uint64(header[8:16]) != uint64(len(out)) {
			return nil, fmt.Errorf("invalid journal frame")
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(f, data); err != nil {
			return nil, err
		}
		checksum := crc32.NewIEEE()
		checksum.Write(header[8:20])
		checksum.Write(data)
		if checksum.Sum32() != binary.LittleEndian.Uint32(header[20:24]) {
			return nil, fmt.Errorf("journal checksum mismatch")
		}
		var es []effects.Effect
		if err := json.Unmarshal(data, &es); err != nil {
			return nil, err
		}
		if len(es) != int(binary.LittleEndian.Uint32(header[16:20])) {
			return nil, fmt.Errorf("journal count mismatch")
		}
		out = append(out, es...)
	}
}

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func diagnosticEvents(n int) []effects.Effect {
	es := make([]effects.Effect, n)
	for i := range es {
		es[i] = effects.Effect{
			Time: time.Unix(1760000000, int64(i)).UTC(),
			Kind: "fs.read", Target: fmt.Sprintf("/workspace/pkg/component-%04d/source-%06d.go", i%256, i),
			Verdict: "allow", Reason: "workspace access", Source: "fuse", PID: uint32(100 + i%8), Detail: "open",
		}
		if i%16 == 0 {
			es[i].Kind, es[i].Source, es[i].Detail = "proc.exec", "seccomp", "execve"
			es[i].Target = "/usr/bin/go"
			es[i].Argv = []string{"go", "build", "./cmd/airbag"}
			es[i].Predict = []string{"fs.write ./airbag"}
		}
	}
	return es
}

func diagnosticMount(path string) string {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "unavailable"
	}
	best, result := 0, "unknown"
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mount := fields[1]
		if mount != "/" && path != mount && !strings.HasPrefix(path, mount+"/") {
			continue
		}
		if len(mount) <= best {
			continue
		}
		best = len(mount)
		result = fmt.Sprintf("filesystem=%s mount=%s", fields[2], mount)
		for _, option := range strings.Split(fields[3], ",") {
			if strings.HasPrefix(option, "fsync=") || option == "volatile" {
				result += " " + option
			}
		}
	}
	return result
}

func storeBytes(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

// BenchmarkAuditStorage reports time per EVENT, not per transaction. Each batch
// is fully present before add is called, so batch=64 does not measure queue wait
// and must not be used to promise a 64x latency win for sequential requests.
func BenchmarkAuditStorage(b *testing.B) {
	const warmup = 256
	versionDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		b.Fatal(err)
	}
	var sqliteVersion string
	if err := versionDB.QueryRow("SELECT sqlite_version()").Scan(&sqliteVersion); err != nil {
		versionDB.Close()
		b.Fatal(err)
	}
	if err := versionDB.Close(); err != nil {
		b.Fatal(err)
	}
	for _, name := range []string{"sqlite-audit", "sqlite-flat", "append-fsync"} {
		for _, batchSize := range []int{1, 64} {
			b.Run(fmt.Sprintf("%s/batch-%d", name, batchSize), func(b *testing.B) {
				dir := b.TempDir()
				mount := diagnosticMount(dir)
				b.Logf("go=%s os=%s arch=%s cpus=%d gomaxprocs=%d sqlite=%s %s ack=after-sync events=%d warmup=%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0), sqliteVersion, mount, b.N, warmup)
				if strings.Contains(mount, "volatile") || strings.Contains(mount, "tmpfs") {
					b.Log("NOT a durable-disk latency measurement: this filesystem is volatile")
				}
				var store diagnosticStore
				var err error
				switch name {
				case "sqlite-audit":
					path := filepath.Join(dir, "effects.db")
					var log *effects.Log
					log, err = effects.Open(path)
					store = &sqliteAudit{log: log, path: path}
				case "sqlite-flat":
					store, err = openFlatSQLite(filepath.Join(dir, "effects.db"))
				case "append-fsync":
					store, err = openAppendJournal(filepath.Join(dir, "effects.log"))
				}
				if err != nil {
					b.Fatal(err)
				}
				closed := false
				defer func() {
					if !closed {
						store.close()
					}
				}()
				if err := syncDirectory(dir); err != nil {
					b.Fatal(err)
				}
				es := diagnosticEvents(warmup + b.N)
				for i := 0; i < warmup; i += batchSize {
					if err := store.add(es[i:min(i+batchSize, warmup)]); err != nil {
						b.Fatal(err)
					}
				}
				latencies := make([]int64, 0, (b.N+batchSize-1)/batchSize)
				b.ReportAllocs()
				b.ResetTimer()
				for i := warmup; i < len(es); i += batchSize {
					start := time.Now()
					if err := store.add(es[i:min(i+batchSize, len(es))]); err != nil {
						b.Fatal(err)
					}
					latencies = append(latencies, time.Since(start).Nanoseconds())
				}
				b.StopTimer()
				liveBytes, err := storeBytes(dir)
				if err != nil {
					b.Fatal(err)
				}
				if err := store.close(); err != nil {
					b.Fatal(err)
				}
				closed = true
				got, err := store.read()
				if err != nil {
					b.Fatal(err)
				}
				if !reflect.DeepEqual(got, es) {
					b.Fatal("reopened log differs in payload or order")
				}
				slices.Sort(latencies)
				for _, p := range []int{50, 95, 99} {
					b.ReportMetric(float64(latencies[(len(latencies)-1)*p/100]), fmt.Sprintf("p%d-ns/batch", p))
				}
				b.ReportMetric(float64(len(latencies))/float64(b.N), "commits/event")
				b.ReportMetric(float64(liveBytes)/float64(len(es)), "live-B/event")
			})
		}
	}
}
