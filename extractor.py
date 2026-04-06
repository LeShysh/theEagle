import re
from hashlib import md5, sha256

from parser import decode_body, get_filename, is_attachment, decode_rfc2047


def extract_address(text: str):
    """Extract the first email address found in a string (e.g. from a From or To header value)."""
    pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+'
    res = re.findall(pattern, text)
    if len(res) > 0:
        return res[-1]
    else:
        return None


def extract_send_ip(headers: dict):
    """Extract the originating sender IP from the last Received header hop."""
    received = headers.get('received', [])
    if isinstance(received, str):
        received = [received]

    if received:
        first_hop = received[-1]
        pattern = r'\b\d{1,3}(?:\.\d{1,3}){3}\b'
        match = re.search(pattern, first_hop)
        return match.group(0) if match else None
    return None


def extract_urls(body: str):
    """Extract and deduplicate all HTTP/HTTPS/www URLs from the email body text."""
    pattern = r'https?://[^\s]+|www\.[^\s]+'
    urls = re.findall(pattern, body)
    data = set()
    for url in urls:
        url = re.split(r'[\"\'<>\s]', url)[0]
        url = url.rstrip('),.')
        data.add(url)
    return list(data)


def extract_auth_res(headers: dict):
    """Parse SPF, DKIM, and DMARC results from the Authentication-Results header."""
    auth = headers.get('authentication-results', '')
    if isinstance(auth, list):
        auth = ' '.join(auth)
    spf = re.search(r'spf=(\w+)', auth)
    dkim = re.search(r'dkim=(\w+)', auth)
    dmarc = re.search(r'dmarc=(\w+)', auth)
    return {
        'spf': spf.group(1) if spf else None,
        'dkim': dkim.group(1) if dkim else None,
        'dmarc': dmarc.group(1) if dmarc else None
    }


def extract_domains(mail_data: dict):
    """Collect unique domains from the sender address, reply-to address, and all extracted URLs."""
    domains = set()

    def extract_domain_from_mail(mail: str):
        return mail.split('@')[1]

    def extract_domain_from_url(url: str):
        if '://' in url:
            url = url.split('://')[1]
        return url.split('/')[0]

    domains.add(extract_domain_from_mail(mail_data.get('from')))
    if mail_data.get('reply_to') is not None:
        domains.add(extract_domain_from_mail(mail_data.get('reply_to')))

    if mail_data.get('urls'):
        for url in mail_data.get('urls'):
            domains.add(extract_domain_from_url(url))

    return list(domains)


def get_text_from_parsed(parsed):
    """Recursively extract plain-text content from a parsed email structure."""
    if parsed.get('type') == 'single':
        headers = parsed.get('headers', {})
        content = parsed.get('content', '')
        try:
            decoded = decode_body(content, headers)
            charset = 'utf-8'
            content_type = headers.get('content-type', '')
            m = re.search(r'charset=([^\s;]+)', content_type, re.IGNORECASE)
            if m:
                charset = m.group(1).strip('"').lower()
            return decoded.decode(charset, errors='replace')
        except Exception:
            return content
    elif parsed.get('type') == 'multipart':
        text = ''
        for part in parsed.get('parts', []):
            text += get_text_from_parsed(part.get('body', {})) + '\n'
        return text
    return ''


def extract_attachments(parsed: dict, extract: bool = True, save_path: str = '.'):
    """
    Walk a parsed email structure and collect attachment metadata (filename, SHA256, MD5, size).
    If extract is True, write each attachment to save_path on disk.
    """
    attachments = []
    if parsed.get('type') == 'multipart':
        for part in parsed.get('parts'):
            headers = part.get('headers')
            body = part.get('body')

            if is_attachment(headers):
                filename = get_filename(headers)

                if body.get('type') == 'single':
                    data = decode_body(body.get('content'), headers)

                    fileinfo = {
                        'filename': filename,
                        'sha256': sha256(data).hexdigest(),
                        'md5': md5(data).hexdigest(),
                        'size': len(data)
                    }

                    if filename and extract:
                        filepath = f'{save_path}/{filename}'
                        with open(filepath, 'wb') as file:
                            file.write(data)

                    attachments.append(fileinfo)

            attachments.extend(extract_attachments(body, extract, save_path))

    return attachments


def extract_data(header: dict, body: str):
    """Orchestrate all header/body extraction and return a unified mail data dict."""
    mail_data = {
        'subject': decode_rfc2047(header.get('subject', '')),
        'from': extract_address(header.get('from')) if header.get('from', None) else None,
        'to': extract_address(header.get('to')) if header.get('to', None) else None,
        'reply_to': extract_address(header.get('reply-to')) if header.get('reply-to', None) else None,
        'sender-ip': extract_send_ip(header),
        'date': header.get('date') if header.get('date', None) else None,
        'message-id': header.get('message-id') if header.get('message-id', None) else None,
        'auth': extract_auth_res(header),
        'urls': extract_urls(body)
    }

    mail_data.update({'domains': extract_domains(mail_data)})

    return mail_data
