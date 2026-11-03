// SPDX-License-Identifier: MIT
package v2rayapi

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type finalState struct {
	gate        sync.RWMutex
	frozen      bool
	unsupported atomic.Bool
}

type finalSnapshot struct {
	Version  int                 `json:"version"`
	RunID    string              `json:"run_id"`
	Counters map[string][2]int64 `json:"counters"`
}

// Hiding replaceable/Upstream fast paths keeps every counted operation behind the gate.
type finalConn struct {
	net.Conn
	state *finalState
}

func (c *finalConn) Read(p []byte) (int, error) {
	c.state.gate.RLock()
	defer c.state.gate.RUnlock()
	if c.state.frozen {
		return 0, net.ErrClosed
	}
	return c.Conn.Read(p)
}

func (c *finalConn) Write(p []byte) (int, error) {
	c.state.gate.RLock()
	defer c.state.gate.RUnlock()
	if c.state.frozen {
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}

func (s *StatsService) guardTCP(conn net.Conn) net.Conn {
	return &finalConn{Conn: conn, state: &s.finalState}
}

type finalPacketConn struct {
	N.PacketConn
	state *finalState
}

func (c *finalPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.state.gate.RLock()
	defer c.state.gate.RUnlock()
	if c.state.frozen {
		return M.Socksaddr{}, net.ErrClosed
	}
	return c.PacketConn.ReadPacket(buffer)
}

func (c *finalPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.state.gate.RLock()
	defer c.state.gate.RUnlock()
	if c.state.frozen {
		buffer.Release()
		return net.ErrClosed
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

func (s *StatsService) guardPacket(conn N.PacketConn) N.PacketConn {
	return &finalPacketConn{PacketConn: conn, state: &s.finalState}
}

func (s *StatsService) writeFinal() error {
	path := os.Getenv("VGB_FINAL_STATS")
	if s == nil || path == "" {
		return nil
	}
	runID := os.Getenv("BRIDGE_RUN_ID")
	if !filepath.IsAbs(path) || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(runID) {
		return errors.New("invalid final counter destination or generation")
	}
	// The pinned v2ray cleanup runs after network/connection cleanup; wait for their last I/O.
	s.finalState.gate.Lock()
	defer s.finalState.gate.Unlock()
	s.finalState.frozen = true
	if s.finalState.unsupported.Load() {
		return errors.New("untracked flow cannot produce a final counter snapshot")
	}
	snapshot := finalSnapshot{Version: 1, RunID: runID, Counters: make(map[string][2]int64)}
	s.access.Lock()
	for user := range s.users {
		var totals [2]int64
		for index, direction := range []string{"uplink", "downlink"} {
			if counter := s.counters["user>>>"+user+">>>traffic>>>"+direction]; counter != nil {
				totals[index] = counter.Load()
			}
		}
		snapshot.Counters[user] = totals
	}
	s.access.Unlock()
	for _, totals := range snapshot.Counters {
		if totals[0] < 0 || totals[1] < 0 {
			return errors.New("invalid final counter value")
		}
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".final-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err = file.Write(payload); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
