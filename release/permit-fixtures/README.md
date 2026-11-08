# Release permit fixtures

Recorded model answers for `release-rehearsal.yml`. The rehearsal feeds them to
`scripts/release/release_permit.py review --fixtures` so the permit pipeline
runs end to end with no network call and no spend. `deny/` must make the
reducer return DENY. `release.yml` never uses these files.
