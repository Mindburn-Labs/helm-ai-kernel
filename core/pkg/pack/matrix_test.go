package pack_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/pack"
)

func TestCheckCompatibility_KernelVersion(t *testing.T) {
	tests := []struct {
		name          string
		constraint    string
		kernelVersion string
		wantErr       bool
	}{
		{
			name:          "No Constraint",
			constraint:    "",
			kernelVersion: "1.2.3",
			wantErr:       false,
		},
		{
			name:          "Exact Match",
			constraint:    "1.2.3",
			kernelVersion: "1.2.3",
			wantErr:       false,
		},
		{
			name:          "Range Match",
			constraint:    ">= 1.2.0",
			kernelVersion: "1.3.0",
			wantErr:       false,
		},
		{
			name:          "Mismatch",
			constraint:    ">= 2.0.0",
			kernelVersion: "1.9.9",
			wantErr:       true,
		},
		{
			name:          "Invalid Kernel",
			constraint:    ">= 1.0.0",
			kernelVersion: "invalid-semver",
			wantErr:       true,
		},
		{
			name:          "Invalid Constraint",
			constraint:    "invalid-constraint",
			kernelVersion: "1.0.0",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := pack.PackManifest{
				PackID: "test-pack",
				ApplicabilityConstraints: &pack.ApplicabilityConstraints{
					KernelVersion: tt.constraint,
				},
			}
			err := pack.CheckCompatibility(manifest, tt.kernelVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckCompatibility() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckDependency(t *testing.T) {
	installed := []pack.PackVersion{
		{
			PackName: "base-pack",
			Version:  "1.0.0",
		},
		{
			PackName: "utils-pack",
			Version:  "2.5.0",
		},
	}

	tests := []struct {
		name    string
		dep     pack.PackDependency
		wantErr bool
	}{
		{
			name: "Dependency Met",
			dep: pack.PackDependency{
				PackName:    "base-pack",
				VersionSpec: ">= 1.0.0",
				Optional:    false,
			},
			wantErr: false,
		},
		{
			name: "Dependency Met Exact",
			dep: pack.PackDependency{
				PackName:    "utils-pack",
				VersionSpec: "2.5.0",
				Optional:    false,
			},
			wantErr: false,
		},
		{
			name: "Dependency Version Mismatch",
			dep: pack.PackDependency{
				PackName:    "base-pack",
				VersionSpec: "> 1.5.0",
				Optional:    false,
			},
			wantErr: true,
		},
		{
			name: "Dependency Missing Required",
			dep: pack.PackDependency{
				PackName:    "missing-pack",
				VersionSpec: "*",
				Optional:    false,
			},
			wantErr: true,
		},
		{
			name: "Dependency Missing Optional",
			dep: pack.PackDependency{
				PackName:    "missing-pack",
				VersionSpec: "*",
				Optional:    true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pack.CheckDependency(tt.dep, installed)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckDependency() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
