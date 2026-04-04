# Idea
The tool offeres a easy command line interface the analyses .eml files for security relevant infos. This infos include:
- Basic Info extraction (sender, receiver, subject, etc.)
- SPF check
- DMARC check
- DKIM check
- Attachment extractor
- URL extractor

# Usage
```commandline
usage: main.py [-h] [-f FILE] [-e [EXTRACT]] [--vt] [--vt-key VT_KEY]

options:
  -h, --help              show this help message and exit
  -f, --file FILE         The path to the .eml to analyse
  -e, --extract EXTRACT   Extract attachments (optionally specify output directory)
  --vt                    Upload indicators to VT for a verdict
  --vt-key VT_KEY         VirusTotal API key
```
