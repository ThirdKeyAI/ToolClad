// Package main provides the toolclad CLI for validating, running, testing,
// and inspecting ToolClad manifests.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/thirdkeyai/toolclad/pkg/executor"
	"github.com/thirdkeyai/toolclad/pkg/manifest"
	"github.com/thirdkeyai/toolclad/pkg/validator"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "toolclad",
		Short: "ToolClad: declarative tool interface contracts for agentic runtimes",
	}

	rootCmd.AddCommand(validateCmd())
	rootCmd.AddCommand(runCmd())
	rootCmd.AddCommand(schemaCmd())
	rootCmd.AddCommand(testCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <manifest>",
		Short: "Validate a .clad.toml manifest file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			m, err := manifest.LoadManifest(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s  ERROR: %v\n", path, err)
				return err
			}

			// Validate that all arg types are known.
			supported := validator.SupportedTypes()
			supportedSet := make(map[string]bool)
			for _, t := range supported {
				supportedSet[t] = true
			}

			for name, arg := range m.Args {
				if !supportedSet[arg.Type] {
					fmt.Fprintf(os.Stderr, "%s  ERROR: arg %q has unknown type %q\n", path, name, arg.Type)
					return fmt.Errorf("unknown type %q for arg %q", arg.Type, name)
				}
			}

			fmt.Printf("%s  OK\n", path)
			fmt.Printf("  Tool:    %s v%s\n", m.Tool.Name, m.Tool.Version)
			fmt.Printf("  Binary:  %s\n", m.Tool.Binary)
			fmt.Printf("  Risk:    %s\n", m.Tool.RiskTier)
			fmt.Printf("  Args:    %d (%d required)\n", len(m.Args), len(m.RequiredArgs()))
			fmt.Printf("  Timeout: %ds\n", m.Tool.TimeoutSeconds)
			return nil
		},
	}
}

func runCmd() *cobra.Command {
	var argFlags []string

	cmd := &cobra.Command{
		Use:   "run <manifest> [--arg key=value ...]",
		Short: "Execute a tool using its manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			m, err := manifest.LoadManifest(path)
			if err != nil {
				return err
			}

			toolArgs, err := parseArgFlags(argFlags)
			if err != nil {
				return err
			}

			envelope, err := executor.Execute(m, toolArgs)
			if err != nil {
				// Still print the envelope for diagnostics.
				printJSON(envelope)
				return err
			}

			printJSON(envelope)
			if envelope.Status != "success" {
				return fmt.Errorf("execution status: %s", envelope.Status)
			}
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&argFlags, "arg", nil, "Tool argument in key=value format (repeatable)")
	return cmd
}

func schemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema <manifest>",
		Short: "Output the MCP JSON schema for a tool",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			m, err := manifest.LoadManifest(path)
			if err != nil {
				return err
			}

			schema := executor.GenerateMCPSchema(m)
			printJSON(schema)
			return nil
		},
	}
}

func testCmd() *cobra.Command {
	var argFlags []string

	cmd := &cobra.Command{
		Use:   "test <manifest> [--arg key=value ...]",
		Short: "Dry-run a tool invocation (validate and show constructed command)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			m, err := manifest.LoadManifest(path)
			if err != nil {
				return err
			}

			toolArgs, err := parseArgFlags(argFlags)
			if err != nil {
				return err
			}

			fmt.Printf("  Manifest:  %s\n", path)

			command, err := executor.DryRun(m, toolArgs)
			if err != nil {
				return err
			}
			fmt.Printf("  Command:   %s\n", command)

			if m.Tool.Cedar != nil {
				fmt.Printf("  Cedar:     %s / %s\n", m.Tool.Cedar.Resource, m.Tool.Cedar.Action)
			}
			fmt.Printf("  Timeout:   %ds\n", m.Tool.TimeoutSeconds)
			fmt.Printf("  Risk:      %s\n", m.Tool.RiskTier)
			fmt.Println()
			fmt.Println("  [dry run -- command not executed]")
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&argFlags, "arg", nil, "Tool argument in key=value format (repeatable)")
	return cmd
}

// parseArgFlags parses --arg key=value flags into a map.
func parseArgFlags(flags []string) (map[string]string, error) {
	result := make(map[string]string)
	for _, f := range flags {
		idx := strings.IndexByte(f, '=')
		if idx < 1 {
			return nil, fmt.Errorf("invalid --arg format %q: expected key=value", f)
		}
		key := strings.TrimSpace(f[:idx])
		if _, exists := result[key]; key == "" || exists {
			return nil, fmt.Errorf("argument names must be nonempty and unique")
		}
		val := f[idx+1:]
		result[key] = val
	}
	return result, nil
}

// printJSON marshals a value to indented JSON and writes it to stdout.
func printJSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling JSON: %v\n", err)
		return
	}
	fmt.Println(string(data))
}
