// SPDX-License-Identifier: MIT
package v2rayapi

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type finalTestConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *finalTestConn) Read(p []byte) (int, error) {
	close(c.started)
	<-c.release
	return copy(p, "end"), nil
}
func (c *finalTestConn) Close() error                { c.once.Do(func() { close(c.release) }); return nil }
func (c *finalTestConn) Write(p []byte) (int, error) { return len(p), nil }

func finalTestService(t *testing.T) (*StatsService, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "final.json")
	t.Setenv("VGB_FINAL_STATS", path)
	t.Setenv("BRIDGE_RUN_ID", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	return NewStatsService(option.V2RayStatsServiceOptions{Enabled: true, Users: []string{"alice", "idle"}}), path
}

func TestFinalSnapshotWaitsForCountedIOAndRejectsLateIO(t *testing.T) {
	s, path := finalTestService(t)
	up := &atomic.Int64{}
	s.counters["user>>>alice>>>traffic>>>uplink"] = up
	raw := &finalTestConn{started: make(chan struct{}), release: make(chan struct{})}
	conn := s.guardTCP(bufio.NewInt64CounterConn(raw, []*atomic.Int64{up}, nil))
	readDone := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 8)); readDone <- err }()
	<-raw.started
	finalDone := make(chan error, 1)
	go func() { finalDone <- s.writeFinal() }()
	select {
	case err := <-finalDone:
		t.Fatalf("snapshot passed in-flight I/O: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	raw.Close()
	select {
	case err := <-finalDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("finalization did not drain")
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result finalSnapshot
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || result.RunID != os.Getenv("BRIDGE_RUN_ID") || result.Counters["alice"][0] != 3 || result.Counters["idle"] != [2]int64{} {
		t.Fatalf("wrong final snapshot: %+v", result)
	}
	if _, err := conn.Read(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late read accepted")
	}
	if _, err := conn.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late write accepted")
	}
	if up.Load() != 3 {
		t.Fatal("final counters changed")
	}
	if _, replaceable := conn.(interface{ Upstream() any }); replaceable {
		t.Fatal("I/O gate can be bypassed")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("snapshot is not private")
	}
}

type finalTestPacket struct{ N.PacketConn }

func (c *finalTestPacket) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	buffer.Write([]byte("udp"))
	return M.Socksaddr{}, nil
}
func (c *finalTestPacket) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func TestFinalPacketGateAndUnsupportedFlow(t *testing.T) {
	s, _ := finalTestService(t)
	up, down := &atomic.Int64{}, &atomic.Int64{}
	conn := s.guardPacket(bufio.NewInt64CounterPacketConn(&finalTestPacket{}, []*atomic.Int64{up}, nil, []*atomic.Int64{down}, nil))
	buffer := buf.NewSize(16)
	if _, err := conn.ReadPacket(buffer); err != nil {
		t.Fatal(err)
	}
	if err := conn.WritePacket(buffer, M.Socksaddr{}); err != nil {
		t.Fatal(err)
	}
	if up.Load() != 3 || down.Load() != 3 {
		t.Fatal("packet counters incorrect")
	}
	if err := s.writeFinal(); err != nil {
		t.Fatal(err)
	}
	late := buf.NewSize(16)
	if _, err := conn.ReadPacket(late); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late packet read accepted")
	}
	if err := conn.WritePacket(late, M.Socksaddr{}); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late packet write accepted")
	}
	if up.Load() != 3 || down.Load() != 3 {
		t.Fatal("packet counters changed after finalization")
	}
	s2 := NewStatsService(option.V2RayStatsServiceOptions{Enabled: true, Users: []string{"alice"}})
	s2.finalState.unsupported.Store(true)
	if err := s2.writeFinal(); err == nil {
		t.Fatal("unsupported flow was finalized")
	}
}

func TestFinalSnapshotFailureDoesNotCreateAValidFile(t *testing.T) {
	s, path := finalTestService(t)
	t.Setenv("VGB_FINAL_STATS", filepath.Join(path, "missing", "final.json"))
	if err := s.writeFinal(); err == nil {
		t.Fatal("write failure ignored")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed snapshot created a file")
	}
	t.Setenv("BRIDGE_RUN_ID", "wrong-generation")
	if err := s.writeFinal(); err == nil {
		t.Fatal("invalid generation accepted")
	}
}
