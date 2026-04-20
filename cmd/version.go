package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var Version = "1.0.0"
var BuildDate = "unknown"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print SpringHawk version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("SpringHawk v%s (built %s)\n", Version, BuildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
