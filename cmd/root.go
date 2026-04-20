package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "springhawk",
	Short: "Spring Boot Security Scanner — pentest and audit your Spring applications",
	Long: `SpringHawk is a comprehensive security testing tool for Spring Boot applications.
It performs remote vulnerability scanning, local static analysis, and OSINT asset discovery.

Use it for authorized security testing of your own applications only.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.springhawk.yaml)")
	rootCmd.PersistentFlags().StringP("output", "o", "", "output file path")
	rootCmd.PersistentFlags().String("format", "terminal", "output format: terminal|json|html")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "suppress non-essential output")
	rootCmd.PersistentFlags().Bool("no-color", false, "disable colored terminal output")

	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))      //nolint:errcheck
	viper.BindPFlag("format", rootCmd.PersistentFlags().Lookup("format"))      //nolint:errcheck
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))    //nolint:errcheck
	viper.BindPFlag("no-color", rootCmd.PersistentFlags().Lookup("no-color")) //nolint:errcheck
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".springhawk")
	}
	viper.AutomaticEnv()
	viper.ReadInConfig() //nolint:errcheck
}
