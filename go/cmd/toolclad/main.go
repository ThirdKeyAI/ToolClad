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
	var allowUnknownKeys bool

	cmd := &cobra.Command{
		Use:   "validate <manifest>",
		Short: "Validate a .clad.toml manifest file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			m, err := loadManifest(path, manifest.LoadOptions{
				AllowUnknownKeys: allowUnknownKeys,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s  ERROR: %v\n", path, err)
				return err
			}

			// LoadManifest has already compiled [command] into its canonical
			// exec form (or accepted another backend), so an exec-only
			// manifest is valid here.
			fmt.Printf("%s  OK\n", path)
			fmt.Printf("  Tool:    %s v%s\n", m.Tool.Name, m.Tool.Version)
			fmt.Printf("  Binary:  %s\n", m.Tool.Binary)
			fmt.Printf("  Risk:    %s\n", m.Tool.RiskTier)
			fmt.Printf("  Args:    %d (%d required)\n", len(m.Args), len(m.RequiredArgs()))
			fmt.Printf("  Timeout: %ds\n", m.Tool.TimeoutSeconds)
			switch {
			case m.Command.Executor != "":
				fmt.Printf("  Command: executor %s\n", m.Command.Executor)
			case len(m.Command.Exec) > 0:
				fmt.Printf("  Command: %s\n", executor.FormatArgv(m.Command.Exec))
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&allowUnknownKeys, "allow-unknown-keys", false,
		"Report unknown manifest keys as warnings instead of refusing to load")
	return cmd
}

func runCmd() *cobra.Command {
	var argFlags []string
	var approve bool

	cmd := &cobra.Command{
		Use:   "run <manifest> [--arg key=value ...]",
		Short: "Execute a tool using its manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			m, err := loadManifest(path, manifest.LoadOptions{})
			if err != nil {
				return err
			}

			toolArgs, err := parseArgFlags(argFlags)
			if err != nil {
				return err
			}

			// Without --approve the default policy gate decides: a
			// manifest with human_approval = true or a high/critical
			// risk_tier is refused before anything runs.
			gate := executor.Gate(executor.DefaultGate)
			if approve {
				gate = executor.ApproveGate
			}
			cmd.SilenceUsage = true
			envelope, err := executor.ExecuteWithGate(m, toolArgs, gate)
			if err != nil {
				// Still print the envelope for diagnostics. A gate
				// denial has none: nothing was executed.
				if envelope != nil {
					printJSON(envelope)
				}
				return err
			}

			printJSON(envelope)
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&argFlags, "arg", nil, "Tool argument in key=value format (repeatable)")
	cmd.Flags().BoolVar(&approve, "approve", false,
		"Approve this run explicitly, bypassing the default policy gate (human_approval, high/critical risk_tier)")
	return cmd
}

func schemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema <manifest>",
		Short: "Output the MCP JSON schema for a tool",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			m, err := loadManifest(path, manifest.LoadOptions{})
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
			m, err := loadManifest(path, manifest.LoadOptions{})
			if err != nil {
				return err
			}

			toolArgs, err := parseArgFlags(argFlags)
			if err != nil {
				return err
			}

			fmt.Printf("  Manifest:  %s\n", path)

			// Validate each argument and display results. Track the first
			// validation failure so we can return a non-zero exit code
			// after the dry-run output is printed — CI consumers gate on
			// this, and silently exiting 0 on a FAIL line was masking
			// every validator refusal.
			fmt.Printf("  Arguments: ")
			first := true
			var firstFailure error
			for _, argDef := range m.ArgsSorted() {
				val, provided := toolArgs[argDef.Name]
				if !provided {
					if argDef.Required {
						fmt.Printf("\n  ERROR: missing required argument %q\n", argDef.Name)
						return fmt.Errorf("missing required argument: %q", argDef.Name)
					}
					if argDef.Default != nil {
						val = fmt.Sprintf("%v", argDef.Default)
					} else {
						continue
					}
				}

				// allow_whitespace is honored only when the manifest
				// declared exec = [...] itself.
				validated, vErr := validator.ValidateArgWithCustomTypesIn(argDef, val, m.CustomTypes, m.Command.ExecWasDeclared, m.Scope)
				status := "OK"
				if vErr != nil {
					status = fmt.Sprintf("FAIL: %v", vErr)
					if firstFailure == nil {
						firstFailure = fmt.Errorf("validation failed for %q: %w", argDef.Name, vErr)
					}
				}

				if !first {
					fmt.Printf("             ")
				}
				fmt.Printf("%s=%s (%s: %s)\n", argDef.Name, validated, argDef.Type, status)
				first = false
			}
			if first {
				fmt.Println("(none)")
			}

			// Build argv from the canonical exec form.
			argv, buildErr := executor.BuildCommandArgv(m, toolArgs)
			if buildErr != nil {
				fmt.Printf("  Command:   ERROR: %v\n", buildErr)
				if firstFailure == nil {
					firstFailure = buildErr
				}
			} else {
				fmt.Printf("  Command:   %s\n", executor.FormatArgv(argv))
				argvJSON, _ := json.Marshal(argv)
				fmt.Printf("  Argv:      %s\n", argvJSON)
			}

			if m.Tool.Cedar != nil {
				fmt.Printf("  Cedar:     %s / %s\n", m.Tool.Cedar.Resource, m.Tool.Cedar.Action)
			}
			fmt.Printf("  Timeout:   %ds\n", m.Tool.TimeoutSeconds)
			fmt.Printf("  Risk:      %s\n", m.Tool.RiskTier)
			approval := "not required"
			if d := executor.DefaultGate(m, nil); !d.Allowed {
				approval = "required (" + d.Reason + "); pass --approve to run"
			}
			fmt.Printf("  Approval:  %s\n", approval)
			fmt.Println()
			fmt.Println("  [dry run -- command not executed]")
			return firstFailure
		},
	}

	cmd.Flags().StringArrayVar(&argFlags, "arg", nil, "Tool argument in key=value format (repeatable)")
	return cmd
}

// loadManifest is the one load path every subcommand uses: the library's
// LoadManifestWithOptions discovers toolclad.toml upward from the manifest
// (or TOOLCLAD_CONFIG_FILE) and type-checks every argument against the
// built-in and custom types; ValidateManifestWithCustomTypes then re-checks
// custom-type defaults and the egress lint with the custom types in hand.
func loadManifest(path string, opts manifest.LoadOptions) (*manifest.Manifest, error) {
	m, err := manifest.LoadManifestWithOptions(path, opts)
	if err != nil {
		return nil, err
	}
	if err := validator.ValidateManifestWithCustomTypes(m, m.CustomTypes); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	return m, nil
}

// parseArgFlags parses --arg key=value flags into a map.
func parseArgFlags(flags []string) (map[string]string, error) {
	result := make(map[string]string)
	for _, f := range flags {
		idx := strings.IndexByte(f, '=')
		if idx < 1 {
			return nil, fmt.Errorf("invalid --arg format %q: expected key=value", f)
		}
		key := f[:idx]
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
