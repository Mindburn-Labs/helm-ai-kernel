package pack

import ()

func makeTestPacks() []ResolvedPack {
	return []ResolvedPack{
		{
			PackID: "pack-1",
			Manifest: PackManifest{
				Name:    "auth-pack",
				Version: "1.0.0",
				Capabilities: []string{
					"auth",
				},
			},
			ContentHash: "sha256:abc123",
		},
		{
			PackID: "pack-2",
			Manifest: PackManifest{
				Name:    "payment-pack",
				Version: "1.0.0",
				Capabilities: []string{
					"payment",
				},
			},
			ContentHash: "sha256:def456",
		},
	}
}
