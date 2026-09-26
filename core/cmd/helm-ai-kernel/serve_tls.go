package main

// quantum_posture: the API listener serves classical TLS 1.2+ (pkg/servetls);
// no post-quantum or hybrid key exchange is claimed.

import (
	"crypto/tls"
	"os"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/servetls"
)

const (
	serveTLSCertFileEnv     = servetls.EnvCertFile
	serveTLSKeyFileEnv      = servetls.EnvKeyFile
	serveTLSClientCAFileEnv = servetls.EnvClientCAFile
	serveTLSClientAuthEnv   = servetls.EnvClientAuth

	serveTLSClientAuthRequire       = servetls.ClientAuthRequire
	serveTLSClientAuthVerifyIfGiven = servetls.ClientAuthVerifyIfGiven
)

// serveTLSConfigFromEnv returns the API listener's TLS configuration, or nil
// when the listener stays plain HTTP (servetls.ConfigFromEnv).
func serveTLSConfigFromEnv() (*tls.Config, error) { return servetls.ConfigFromEnv(os.Getenv) }
