// Command safeshare finds and redacts secrets and personal data in text
// before it is shared. It works offline and never prints a detected value.
package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/Yamen-M/safeshare/internal/config"
	"github.com/Yamen-M/safeshare/internal/detectors"
	"github.com/Yamen-M/safeshare/internal/output"
	"github.com/Yamen-M/safeshare/internal/redactor"
	"github.com/Yamen-M/safeshare/internal/rules"
	"github.com/Yamen-M/safeshare/internal/scanner"
	"github.com/spf13/cobra"
)

// maxInput is the largest input SafeShare will read.
// ponytail: the whole input is held in memory; scan in overlapping chunks if
// larger files need support.
const maxInput = 100 << 20

// errFindings makes scan exit with code 1 without printing an error.
var errFindings = errors.New("findings detected")

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

// run executes the CLI and returns the exit code: 0 for success, 1 when scan
// found something, 2 for invalid arguments or unreadable input.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	root := newRoot()
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	switch err := root.Execute(); {
	case err == nil:
		return 0
	case errors.Is(err, errFindings):
		return 1
	default:
		fmt.Fprintln(stderr, "safeshare:", err)
		return 2
	}
}

type options struct {
	format, confidence, rulesPath, allowlistPath string
	quiet, stdin, inPlace, dryRun                bool
}

func newRoot() *cobra.Command {
	o := &options{}
	root := &cobra.Command{
		Use:           "safeshare",
		Short:         "Share debugging context, not your secrets",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := root.PersistentFlags()
	pf.StringVar(&o.format, "format", "text", "format of the findings report: text or json")
	pf.StringVar(&o.confidence, "confidence", "", "lowest confidence to act on: low, medium or high (default medium)")
	pf.StringVar(&o.rulesPath, "rules", "", "YAML file with custom rules")
	pf.StringVar(&o.allowlistPath, "allowlist", "", "YAML file with values that are never reported")
	pf.BoolVarP(&o.quiet, "quiet", "q", false, "do not print the findings report")

	scan := &cobra.Command{
		Use:   "scan [file]",
		Short: "Report sensitive values; exits 1 if any are found",
		Long:  "Report sensitive values in a file or standard input.\nOnly findings are printed, never the input itself.",
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := output.New(o.format)
			if err != nil {
				return err
			}
			_, report, err := o.analyze(args, cmd.InOrStdin())
			if err != nil {
				return err
			}
			if !o.quiet {
				if err := format.Format(cmd.OutOrStdout(), report); err != nil {
					return err
				}
			}
			if len(report.Findings) > 0 {
				return errFindings
			}
			return nil
		},
	}
	scan.Flags().BoolVar(&o.stdin, "stdin", false, "read from standard input")

	redact := &cobra.Command{
		Use:   "redact [file]",
		Short: "Print the input with sensitive values replaced by placeholders",
		Long:  "Print the input with sensitive values replaced by placeholders.\nStandard output carries only the sanitized text; the findings report goes to standard error.",
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := output.New(o.format)
			if err != nil {
				return err
			}
			if o.inPlace && o.stdin {
				return errors.New("--in-place needs a file, not --stdin")
			}
			input, report, err := o.analyze(args, cmd.InOrStdin())
			if err != nil {
				return err
			}
			clean := redactor.Redact(input, report.Findings)
			switch {
			case o.dryRun:
				for i := range report.Findings {
					report.Findings[i].Redacted = false // nothing was written anywhere
				}
			case o.inPlace:
				if err := replaceFile(args[0], clean); err != nil {
					return err
				}
			default:
				if _, err := cmd.OutOrStdout().Write(clean); err != nil {
					return err
				}
			}
			if o.quiet {
				return nil
			}
			return format.Format(cmd.ErrOrStderr(), report)
		},
	}
	redact.Flags().BoolVar(&o.stdin, "stdin", false, "read from standard input")
	redact.Flags().BoolVar(&o.inPlace, "in-place", false, "overwrite the file instead of printing")
	redact.Flags().BoolVar(&o.dryRun, "dry-run", false, "report what would be redacted without printing or writing it")

	rulesCmd := &cobra.Command{Use: "rules", Short: "Work with detection rules"}
	rulesCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List active detectors",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, err := o.engine()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tCATEGORY\tCONFIDENCE")
			for _, d := range eng.detectors {
				fmt.Fprintf(w, "%s\t%s\t%s\n", d.Name(), d.Category(), d.Confidence())
			}
			return w.Flush()
		},
	})

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create " + config.FileName + " in the current directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.OpenFile(config.FileName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("%s already exists; it was not changed", config.FileName)
			}
			if err != nil {
				return err
			}
			if _, err := f.WriteString(config.Template); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			if !o.quiet {
				fmt.Fprintln(cmd.ErrOrStderr(), "created", config.FileName)
			}
			return nil
		},
	}

	root.AddCommand(scan, redact, rulesCmd, initCmd)
	return root
}

type engine struct {
	detectors []scanner.Detector
	allowed   func([]byte) bool
	min       scanner.Confidence
}

// engine builds the detectors from the config file and flags. Flags win.
func (o *options) engine() (*engine, error) {
	cfg, err := config.Load(config.FileName)
	if err != nil {
		return nil, err
	}
	level := "medium"
	if cfg.Confidence != "" {
		level = cfg.Confidence
	}
	if o.confidence != "" {
		level = o.confidence
	}
	min, err := scanner.ParseConfidence(level)
	if err != nil {
		return nil, err
	}

	var custom []rules.Rule
	if o.rulesPath != "" {
		if custom, err = rules.Load(o.rulesPath); err != nil {
			return nil, err
		}
	}
	dets, err := detectors.All(custom, cfg.EntropyThreshold)
	if err != nil {
		return nil, err
	}
	if want := config.Categories(cfg.Detectors); want != nil {
		known := map[string]bool{}
		var kept []scanner.Detector
		for _, d := range dets {
			known[d.Category()] = true
			if want[d.Category()] {
				kept = append(kept, d)
			}
		}
		for name := range want {
			if !known[name] {
				return nil, fmt.Errorf("%s: unknown detector %q; see \"safeshare rules list\"", config.FileName, name)
			}
		}
		dets = kept
	}

	allow := cfg.Allowlist
	if o.allowlistPath != "" {
		extra, err := config.LoadAllowlist(o.allowlistPath)
		if err != nil {
			return nil, err
		}
		allow = allow.Merge(extra)
	}
	allowed, err := allow.Matcher()
	if err != nil {
		return nil, err
	}
	return &engine{dets, allowed, min}, nil
}

// analyze reads the input and scans it. Findings below the confidence
// threshold are counted in the report instead of being dropped silently.
func (o *options) analyze(args []string, stdin io.Reader) ([]byte, output.Report, error) {
	var report output.Report
	eng, err := o.engine()
	if err != nil {
		return nil, report, err
	}
	source, input, err := o.read(args, stdin)
	if err != nil {
		return nil, report, err
	}
	report.Source = source
	for _, f := range scanner.Scan(source, input, eng.detectors, eng.allowed) {
		if f.Confidence >= eng.min {
			report.Findings = append(report.Findings, f)
		} else {
			report.Hidden++
		}
	}
	return input, report, nil
}

func (o *options) read(args []string, stdin io.Reader) (source string, input []byte, err error) {
	switch {
	case o.stdin && len(args) > 0:
		return "", nil, errors.New("give either a file or --stdin, not both")
	case o.stdin:
		source = scanner.StdinPath
		input, err = io.ReadAll(io.LimitReader(stdin, maxInput+1))
	case len(args) != 1:
		return "", nil, errors.New("expected exactly one file, or --stdin")
	default:
		source = args[0]
		var info fs.FileInfo
		if info, err = os.Stat(source); err != nil {
			return "", nil, err
		}
		if info.IsDir() {
			return "", nil, fmt.Errorf("%s is a directory", source)
		}
		if info.Size() > maxInput {
			return "", nil, tooLarge(source)
		}
		input, err = os.ReadFile(source)
	}
	if err != nil {
		return "", nil, err
	}
	if len(input) > maxInput {
		return "", nil, tooLarge(source)
	}
	return source, input, nil
}

func tooLarge(source string) error {
	return fmt.Errorf("%s is larger than the %d MB limit; nothing was scanned", source, maxInput>>20)
}

// replaceFile writes data to a temporary file next to path and renames it
// over path, so a failure cannot leave a half-written file behind.
func replaceFile(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".safeshare-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename has happened
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), info.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
