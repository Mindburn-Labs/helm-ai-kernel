package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto/tee/collateral"
)

func main() {
	bundlePath := flag.String("bundle", "pkg/crypto/tee/collateral/testdata/offline_bundle.json", "offline collateral bundle path")
	flag.Parse()

	bundle, err := collateral.Load(*bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tee-collateral: load: %v\n", err)
		os.Exit(1)
	}
	if err := collateral.Validate(bundle, time.Now().UTC()); err != nil {
		fmt.Fprintf(os.Stderr, "tee-collateral: validate: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("tee-collateral: validated %d offline documents\n", len(bundle.Documents))
}
