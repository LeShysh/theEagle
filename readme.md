# theEagle — EML Email Analyser

A command-line tool for analysing `.eml` files for security-relevant information. Useful for phishing triage, email forensics, and threat intelligence workflows.

## Features

- **Header analysis** — sender, recipient, subject, date, message-ID, reply-to, sender IP
- **Authentication checks** — SPF, DKIM, DMARC results parsed from `Authentication-Results`
- **Attachment extraction** — saves attachments to disk and computes SHA256/MD5 hashes
- **URL extraction** — pulls all `http`/`https`/`www` links from the email body
- **Domain extraction** — collects unique domains from sender, reply-to, and URLs
- **VirusTotal lookups** — queries VT for verdicts on domains, IPs, and attachment hashes

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```
usage: main.py [-h] -f FILE [-e [EXTRACT]] [--vt] [-o {json,human-readable}]

options:
  -h, --help                        Show this help message and exit
  -f FILE, --file FILE              Path to the .eml file to analyse
  -e [EXTRACT], --extract [EXTRACT] Extract attachments (optionally specify output directory)
  --vt                              Look up indicators on VirusTotal (requires VT_KEY env var)
  -o {json,human-readable}          Output format (default: human-readable)
```

## Examples

Analyse an email and print a formatted table:
```bash
python main.py -f sample.eml
```

Extract attachments to a specific directory:
```bash
python main.py -f sample.eml -e ./attachments
```

Run VirusTotal lookups and output as JSON:
```bash
VT_KEY=your_api_key python main.py -f sample.eml --vt -o json
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VT_KEY` | VirusTotal API key (required when using `--vt`) |

## Dependencies

- [requests](https://pypi.org/project/requests/) — HTTP requests for VirusTotal API
- [rich](https://pypi.org/project/rich/) — terminal output formatting
