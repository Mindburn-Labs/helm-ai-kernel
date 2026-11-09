package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/tonacton"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/custody"
)

const (
	envTONActonBin       = "HELM_GATEWAY_TON_ACTON_BIN"
	envTONActonWorkspace = "HELM_GATEWAY_TON_ACTON_WORKSPACE"
	envTONRPCURL         = "HELM_GATEWAY_TON_TESTNET_RPC_URL"
	envTONMaxSpend       = "HELM_GATEWAY_TON_TESTNET_MAX_SPEND"
	// envTONIsolationCmd is a JSON array: the command prefix that runs Acton
	// under another uid or in a container with no access to the gateway's
	// credential files. Operations that run over tenant files need it.
	envTONIsolationCmd = "HELM_GATEWAY_TON_ACTON_ISOLATION_CMD"
)

// tonActonFromEnv wires the TON Acton adapter and its wallet custody. Nothing
// configured returns (nil, nil, nil). The testnet operations exist only when the
// RPC URL and the wallets file are both set; one without the other is an error,
// so the gateway never broadcasts what it cannot read back.
func tonActonFromEnv(getenv func(string) string) (*tonacton.Adapter, *custody.TONWallets, error) {
	bin := strings.TrimSpace(getenv(envTONActonBin))
	workspace := strings.TrimSpace(getenv(envTONActonWorkspace))
	rpc := strings.TrimSpace(getenv(envTONRPCURL))
	wallets, err := custody.TONWalletsFromEnv(getenv)
	if err != nil {
		return nil, nil, err
	}
	if bin == "" && workspace == "" {
		if rpc != "" || wallets != nil {
			return nil, nil, fmt.Errorf("%s and %s are required for the TON testnet settings", envTONActonBin, envTONActonWorkspace)
		}
		return nil, nil, nil
	}
	if bin == "" || workspace == "" {
		return nil, nil, fmt.Errorf("set both %s and %s, or neither", envTONActonBin, envTONActonWorkspace)
	}
	if (rpc == "") != (wallets == nil) {
		return nil, nil, fmt.Errorf("set both %s and %s, or neither", envTONRPCURL, custody.EnvTONWalletsFile)
	}
	cfg := tonacton.Config{Binary: bin, WorkspaceRoot: workspace, MaxTestnetSpend: strings.TrimSpace(getenv(envTONMaxSpend))}
	if raw := strings.TrimSpace(getenv(envTONIsolationCmd)); raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg.Isolation); err != nil || len(cfg.Isolation) == 0 {
			return nil, nil, fmt.Errorf("%s must be a non-empty JSON array of strings", envTONIsolationCmd)
		}
	}
	if wallets != nil {
		// A secret inside the workspace is inside what tenant code can read.
		root := filepath.Clean(workspace) + string(filepath.Separator)
		for _, f := range wallets.SecretFiles() {
			if strings.HasPrefix(filepath.Clean(f)+string(filepath.Separator), root) || !filepath.IsAbs(f) {
				return nil, nil, fmt.Errorf("a testnet wallet secret file must be an absolute path outside %s", envTONActonWorkspace)
			}
		}
		if len(cfg.Isolation) == 0 {
			return nil, nil, fmt.Errorf("testnet wallets need %s: Acton runs over tenant files while it holds the key", envTONIsolationCmd)
		}
	}
	if rpc != "" {
		if cfg.Chain, err = tonacton.NewToncenter(rpc); err != nil {
			return nil, nil, errors.Join(fmt.Errorf("%s", envTONRPCURL), err)
		}
	}
	adapter, err := tonacton.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	return adapter, wallets, nil
}
