package provision

func (p HetznerProvisioner) Plan(launchID, planHash string) Plan {
	return Plan{
		Provider:       "hetzner",
		LaunchID:       launchID,
		DryRun:         true,
		IdempotencyKey: IdempotencyKey("hetzner", launchID, planHash),
		Resources:      map[string]string{"server": "planned", "firewall": "planned"},
	}
}

type HetznerProvisioner struct {
	DryRun bool
}
