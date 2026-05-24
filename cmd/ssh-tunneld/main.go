// Command ssh-tunneld is the tokyo3-ssh-proxy reverse-tunnel agent.
//
// Runs on every host that should be reachable via ssh-proxyd without
// exposing port 22 to the network. Renews its SSH host certificate from
// certd, dials ssh-proxyd over mTLS, holds a long-lived multiplexed
// outbound connection, and forwards inbound streams to the local
// sshd:127.0.0.1:22 for the actual SSH session.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const appName = "ssh-tunneld"

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
		Short: "tokyo3-ssh-proxy reverse-tunnel agent",
	}
	root.AddCommand(runCmd(), versionCmd())
	return root
}

func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run the tunnel agent in the foreground",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return fmt.Errorf("ssh-tunneld run: not yet implemented")
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
