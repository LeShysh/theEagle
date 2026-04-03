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

main.py /path/to/mail.eml

main.py /path/to/mail.eml -t

main.py /path/to/mail.eml -a /path/to/put/attachments

```
