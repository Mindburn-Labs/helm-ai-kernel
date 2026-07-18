package approvalceremony

import _ "embed"

//go:embed migrations/002_effect_reservation_events.sql
var effectReservationPostgresSchema string
