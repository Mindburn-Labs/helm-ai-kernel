package main

import (
	"sync"
	"time"
)

// maxProxySessions bounds the session table; client-chosen session IDs must
// not grow it without limit.
const maxProxySessions = 4096

// proxySessionLimits enforces --max-iterations and --max-wallclock per caller
// session instead of per process (audit 03-15). Sessions are named by the
// client, so these are loop guards for a cooperating agent, not an
// authorization boundary.
type proxySessionLimits struct {
	mu            sync.Mutex
	maxIterations int
	maxWallclock  time.Duration
	now           func() time.Time
	sessions      map[string]*proxySessionState
}

type proxySessionState struct {
	started    time.Time
	iterations int
}

func newProxySessionLimits(maxIterations int, maxWallclock time.Duration, now func() time.Time) *proxySessionLimits {
	return &proxySessionLimits{
		maxIterations: maxIterations,
		maxWallclock:  maxWallclock,
		now:           now,
		sessions:      make(map[string]*proxySessionState),
	}
}

// admit counts one governed tool call against sessionID and returns the limit
// status it trips, or "" when the call is within the session's limits. A
// session's wallclock starts at its first tool call.
func (l *proxySessionLimits) admit(sessionID string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	state, ok := l.sessions[sessionID]
	if !ok {
		if len(l.sessions) >= maxProxySessions {
			l.evictOldestLocked()
		}
		state = &proxySessionState{started: now}
		l.sessions[sessionID] = state
	}
	state.iterations++
	if l.maxIterations > 0 && state.iterations > l.maxIterations {
		return "PROXY_ITERATION_LIMIT"
	}
	if l.maxWallclock > 0 && now.Sub(state.started) > l.maxWallclock {
		return "PROXY_WALLCLOCK_LIMIT"
	}
	return ""
}

func (l *proxySessionLimits) evictOldestLocked() {
	var oldestID string
	var oldest time.Time
	for id, state := range l.sessions {
		if oldestID == "" || state.started.Before(oldest) {
			oldestID, oldest = id, state.started
		}
	}
	delete(l.sessions, oldestID)
}
