package approvalceremony

import _ "embed"

//go:embed migrations/002_effect_reservation_events.sql
var effectReservationPostgresSchema string

//go:embed migrations/003_effect_closures.sql
var effectClosurePostgresSchema string

//go:embed migrations/004_effect_dispositions.sql
var effectDispositionPostgresSchema string
