package siwc

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Run is the gateway-local sign-in ceremony. There is deliberately no command
// to print/export a bearer token, import Codex credentials, or enable Cloud
// plan usage. The UI integrates safe Account metadata through CP separately.
func Run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if getenv("HELM_DEPLOYMENT_MODE") != "selfhost" {
		return errors.New("ChatGPT plan sign-in is available only in HELM_DEPLOYMENT_MODE=selfhost")
	}
	if len(args) == 0 {
		return errors.New("usage: helm-gateway chatgpt login|status|logout [--store PATH] [--account ID]")
	}
	operation := args[0]
	if operation != "login" && operation != "status" && operation != "logout" {
		return errors.New("unknown ChatGPT connection operation")
	}
	fs := flag.NewFlagSet("chatgpt "+operation, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("store", getenv("HELM_GATEWAY_SIWC_DIR"), "private gateway-local credential directory")
	selected := fs.String("account", "", "saved account registration id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected ChatGPT connection arguments")
	}
	if *dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return ErrStorage
		}
		*dir = filepath.Join(base, "helm", "chatgpt")
	}
	store, err := OpenStore(*dir)
	if err != nil {
		return err
	}
	client := NewClient()
	encoder := json.NewEncoder(stdout)
	switch operation {
	case "login":
		account, err := store.Login(ctx, client, *selected, func(u string) error {
			_, err := fmt.Fprintln(stderr, "Continue with ChatGPT in your browser:\n"+u)
			return err
		})
		if err != nil {
			return err
		}
		return encoder.Encode(account)
	case "status":
		accounts, err := store.Accounts(ctx)
		if err != nil {
			return err
		}
		if *selected != "" {
			for _, account := range accounts {
				if account.ID == *selected {
					return encoder.Encode(account)
				}
			}
			return ErrIdentity
		}
		return encoder.Encode(accounts)
	case "logout":
		if *selected == "" {
			return errors.New("logout requires an explicit --account ID")
		}
		accounts, err := store.Accounts(ctx)
		if err != nil {
			return err
		}
		for _, account := range accounts {
			if account.ID != *selected {
				continue
			}
			confirmed, err := store.Logout(ctx, client, account.Reference())
			if err != nil {
				return err
			}
			if !confirmed {
				_, _ = fmt.Fprintln(stderr, "Local sign-out complete; remote revocation was not confirmed. Disconnect HELM in ChatGPT Settings.")
			}
			return encoder.Encode(struct {
				SignedOut                 bool `json:"signed_out"`
				RemoteRevocationConfirmed bool `json:"remote_revocation_confirmed"`
			}{true, confirmed})
		}
		return ErrIdentity
	}
	return errors.New("unknown ChatGPT connection operation")
}
