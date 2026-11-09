# SafeShare

**Share debugging context, not your secrets.**

SafeShare is a command-line tool that finds secrets and personal data in text
(logs, prompts, code snippets, bug reports) and replaces them with readable
placeholders before you paste that text into an AI tool or a public issue.

```text
Authorization: Bearer sk-example-secret      Authorization: Bearer [REDACTED:TOKEN_1]
Email: alice@example.com                 ->  Email: [REDACTED:EMAIL_1]
token=abc123                                 token=[REDACTED:TOKEN_2]
retry_token=abc123                           retry_token=[REDACTED:TOKEN_2]
```

The same value always gets the same placeholder within one run, so the text
still makes sense to whoever reads it.

- Works offline. It makes no network calls and has no telemetry.
- Never prints a detected value. Reports show a masked preview of at most four characters.
- Runs on Windows, Linux and macOS, and keeps LF or CRLF line endings as they are.

> **Status:** early core release. SARIF output, a GitHub Action, prebuilt
> binaries and fuzz testing are planned but not built yet.

## Limitations

SafeShare does **not** detect every secret, and it never will. Detection is
based on patterns and heuristics, so:

- A secret in an unusual format can pass through unnoticed.
- Ordinary values are sometimes flagged (version numbers that look like IP
  addresses, long IDs that look like card numbers).
- Low-confidence findings are counted in a warning but not redacted unless you
  pass `--confidence low`.

Read the output before you share it. SafeShare lowers the risk; it does not remove it.

## Install

You need [Go](https://go.dev/dl/) 1.24 or newer. The command is the same on every system:

```bash
go install github.com/Yamen-M/safeshare/cmd/safeshare@latest
```

Or build from a clone of this repository:

```bash
go build -o safeshare ./cmd/safeshare
```

On Windows, name the output `safeshare.exe`:

```powershell
go build -o safeshare.exe ./cmd/safeshare
```

## Usage

```text
safeshare scan <file>       report findings; exit code 1 if any are found
safeshare redact <file>     print the text with values replaced
safeshare rules list        show the active detectors
safeshare init              create a .safeshare.yaml with the defaults
```

Both `scan` and `redact` accept `--stdin` instead of a file. `redact` writes
only the sanitized text to standard output and the findings report to standard
error, so it is safe in a pipeline. A file is never modified unless you pass
`--in-place`.

### Bash (Linux, macOS, Git Bash)

```bash
safeshare scan app.log
safeshare redact app.log > app.clean.log
kubectl logs my-pod | safeshare redact --stdin --quiet
```

### macOS clipboard

```bash
pbpaste | safeshare redact --stdin | pbcopy
```

### PowerShell (Windows)

```powershell
safeshare scan .\app.log
safeshare redact .\app.log > app.clean.log
Get-Clipboard -Raw | safeshare redact --stdin | Set-Clipboard
```

Windows PowerShell 5.1 can change the encoding of text piped between programs.
If the text has non-English characters, pass the file path instead of piping.

### Options

| Option | Meaning |
| --- | --- |
| `--confidence low\|medium\|high` | Lowest confidence to act on. Default `medium`. |
| `--format text\|json` | Format of the findings report. |
| `--rules FILE` | Add custom rules, or switch built-in ones off. |
| `--allowlist FILE` | Values that are never reported. |
| `--in-place` | `redact` overwrites the file. |
| `--dry-run` | `redact` reports what it would replace and writes nothing. |
| `--quiet`, `-q` | Do not print the findings report. |

Exit codes: `0` success, `1` `scan` found something, `2` invalid arguments or unreadable input.

### Custom rules

```yaml
rules:
  - name: employee-id
    category: employee_id
    confidence: high
    regex: 'EMP-\d{6}'
  - name: ipv4        # switch a built-in rule off
    enabled: false
```

Regular expressions use Go (RE2) syntax. If a regex has a capture group, only
the first group is replaced.

## License

[MIT](LICENSE)
