from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


def vt_verdict(verdict: dict, sensitivity:int):
    """Convert a VirusTotal last_analysis_stats dict into a single verdict string (malicious/suspicious/benign/unknown)."""
    if verdict.get('malicious') >= sensitivity:
        return 'malicious'
    elif verdict.get('suspicious') >= sensitivity:
        return 'suspicious'
    elif verdict.get('harmless') >= sensitivity:
        return 'benign'
    else:
        return 'unknown'


def vt_lookup(indicator: str, api_key: str, sensitivity:int):
    """Query the VirusTotal API for a given indicator (domain, IP, or hash) and return its verdict string."""
    url = f'https://www.virustotal.com/api/v3/search?query={indicator}'
    headers = {'x-apikey': api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        if len(response.json().get('data', {})) == 0:
            return 'unknown'
        res = response.json().get('data', {})[0].get('attributes', {}).get('last_analysis_stats', {})
        return vt_verdict(res, sensitivity)
    else:
        raise LookupError(f'Failed to perform vt lookup with status code: {response.status_code}')


def verdict_check(mail_data: dict, api_key: str, sensitivity:int):
    """Look up all domains, IPs, and attachment hashes in VirusTotal and return a verdicts dict."""
    lookups = []

    if mail_data.get('attachments'):
        for file in mail_data.get('attachments'):
            lookups.append(('attachments', file.get('filename'), file.get('sha256')))

    if mail_data.get('domains'):
        for domain in mail_data.get('domains'):
            lookups.append(('domains', domain, domain))

    if mail_data.get('sender-ip'):
        lookups.append(('sender-ip', mail_data.get('sender-ip'), mail_data.get('sender-ip')))

    futures = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        for category, label, indicator in lookups:
            future = executor.submit(vt_lookup, indicator, api_key, sensitivity)
            futures[future] = (category, label)

        results = {}
        for future in as_completed(futures):
            category, label = futures[future]
            results[(category, label)] = future.result()

    verdicts = {}
    for (category, label), verdict in results.items():
        verdicts.setdefault(category, {})[label] = verdict

    return verdicts
