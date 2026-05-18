package provision

func (p DigitalOceanProvisioner) Plan(launchID, planHash string) Plan {
	return Plan{
		Provider:       "digitalocean",
		LaunchID:       launchID,
		DryRun:         true,
		IdempotencyKey: IdempotencyKey("digitalocean", launchID, planHash),
		Resources:      map[string]string{"droplet": "planned", "firewall": "planned"},
	}
}

type DigitalOceanProvisioner struct {
	DryRun bool
}
