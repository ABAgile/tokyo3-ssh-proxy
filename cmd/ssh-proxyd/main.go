// Command ssh-proxyd is the tokyo3-ssh-proxy SSH gateway and session recorder.
//
// Acts as the user-facing SSH entry point: terminates each SSH connection,
// validates the user's short-lived cert (issued by certd), enforces RBAC
// from cert extensions, requests a per-session impersonation cert from
// certd, opens a routed stream to the target's ssh-tunneld over an
// existing reverse tunnel, mirrors the PTY into an asciinema recording
// uploaded to S3, and publishes audit events to NATS JetStream.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const appName = "ssh-proxyd"

// Version is overridden at build time via -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   appName,
		Short: "tokyo3-ssh-proxy SSH gateway and session recorder",
	}
	root.AddCommand(serveCmd(), versionCmd())
	return root
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the SSH gateway",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return fmt.Errorf("ssh-proxyd serve: not yet implemented")
		},
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Printf("%s %s\n", appName, Version)
		},
	}
}
