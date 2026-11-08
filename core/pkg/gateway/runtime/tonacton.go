package runtime

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/tonacton"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/custody"
)

const (
	envTONActonBin       = "HELM_GATEWAY_TON_ACTON_BIN"
	envTONActonWorkspace = "HELM_GATEWAY_TON_ACTON_WORKSPACE"
	envTONRPCURL         = "HELM_GATEWAY_TON_TESTNET_RPC_URL"
	envTONMaxSpend       = "HELM_GATEWAY_TON_TESTNET_MAX_SPEND"
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
