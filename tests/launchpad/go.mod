module github.com/Mindburn-Labs/helm-ai-kernel/tests/launchpad

go 1.25.0

require github.com/Mindburn-Labs/helm-ai-kernel/core v0.0.0

require (
	github.com/BurntSushi/toml v1.5.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/Mindburn-Labs/helm-ai-kernel/core => ../../core
