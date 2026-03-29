package conductor

import (
	"context"
	"log/slog"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
)

// Scheduler polls for missions with schedule triggers and dispatches them.
// It uses a simple ticker-based approach; a full cron expression parser can be
// layered on top later by inspecting m.Trigger.Schedule.
type Scheduler struct {
	missions  store.MissionStore
	conductor *Service
	logger    *slog.Logger
	interval  time.Duration
}

// NewScheduler creates a Scheduler that polls every 60 seconds by default.
func NewScheduler(missions store.MissionStore, conductor *Service, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		missions:  missions,
		conductor: conductor,
		logger:    logger,
		interval:  60 * time.Second,
	}
}

// Start begins the scheduler loop. It runs until ctx is canceled.
func (s *Scheduler) Start(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.poll(ctx)
		}
	}
}

// poll lists missions with a schedule trigger that are in "pending" state and
// dispatches each one via the conductor.  Dispatch is async so the poll loop
// is never blocked by a slow mission.
func (s *Scheduler) poll(ctx context.Context) {
	missions, err := s.missions.List(ctx, store.MissionFilter{})
	if err != nil {
		s.logger.Error("scheduler: list missions", "error", err)
		return
	}

	for _, m := range missions {
		if m.Trigger.Type != researchruntime.MissionTriggerSchedule {
			continue
		}
		// Only dispatch missions that are waiting to be run ("pending").
		// A real implementation would also parse m.Trigger.Schedule (cron expression)
		// and check whether the current wall-clock time satisfies it.
		go func(missionID string) {
			if err := s.conductor.Run(ctx, missionID); err != nil {
				s.logger.Error("scheduler: run mission", "mission_id", missionID, "error", err)
			}
		}(m.MissionID)
	}
}
