import requests


def vt_verdict(verdict: dict):
    """Convert a VirusTotal last_analysis_stats dict into a single verdict string (malicious/suspicious/benign/unknown)."""
    if verdict.get('malicious') > 0:
        return 'malicious'
    elif verdict.get('suspicious') > 0:
        return 'suspicious'
    elif verdict.get('harmless') > 0:
        return 'benign'
    else:
        return 'unknown'


def vt_lookup(indicator: str, api_key: str):
    """Query the VirusTotal API for a given indicator (domain, IP, or hash) and return its verdict string."""
    url = f'https://www.virustotal.com/api/v3/search?query={indicator}'
    headers = {'x-apikey': api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        if len(response.json().get('data', {})) == 0:
            return 'unknown'
        res = response.json().get('data', {})[0].get('attributes', {}).get('last_analysis_stats', {})
        return vt_verdict(res)
    else:
        raise LookupError(f'Failed to perform vt lookup with status code: {response.status_code}')


def verdict_check(mail_data: dict, api_key: str):
    """Look up all domains, IPs, and attachment hashes in VirusTotal and return a verdicts dict."""
    verdicts = {}

    if mail_data.get('attachments'):
        files = {}
        for file in mail_data.get('attachments'):
            files.update({file.get('filename'): vt_lookup(file.get('sha256'), api_key)})
        verdicts.update({'attachments': files})

    if mail_data.get('domains'):
        domains = {}
        for domain in mail_data.get('domains'):
            domains.update({domain: vt_lookup(domain, api_key)})
        verdicts.update({'domains': domains})

    if mail_data.get('sender-ip'):
        verdicts.update({'sender-ip': {mail_data.get('sender-ip'): vt_lookup(mail_data.get('sender-ip'), api_key)}})

    return verdicts
