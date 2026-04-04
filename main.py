import argparse
import base64
import quopri
import re
import urllib.parse
from hashlib import sha256, md5

import requests
from pandas.core.dtypes.inference import is_bool


def split_headers_body(raw_email: str):
    raw_email = raw_email.lstrip('\n')
    parts = raw_email.split("\n\n", 1)
    return parts[0], parts[1] if len(parts) > 1 else ''


def parse_body(body: str, headers: dict):
    content_type = headers.get('Content-Type', '')

    if 'multipart' in content_type:
        boundary = extract_boundary(content_type)
        res = parse_multipart(body, boundary)
        res.update({'headers': headers})
        return res
    else:
        return {
            'type': 'single',
            'headers': headers,
            'content': body.strip()
        }


def is_attachment(headers: dict):
    cd = headers.get('Content-Disposition', '')
    return 'attachment' in cd.lower()


def get_filename(headers: dict):
    cd = headers.get('Content-Disposition', '')

    for part in cd.split(';'):
        part = part.strip()

        if part.startswith('filename*='):
            encoded = part.split('=', 1)[1]
            _, _, value = encoded.partition("''")
            return urllib.parse.unquote(value)

        elif part.startswith('filename='):
            return part.split('=', 1)[1].strip('"')

    return None


def extract_attachments(parsed: dict, extract: bool = True, save_path: str = '.'):
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

            attachments.extend(extract_attachments(body, save_path))

    return attachments


def extract_boundary(content_type: str):
    pattern = r'boundary="?([^";]+)"?'
    match = re.search(pattern, content_type, re.IGNORECASE)
    return match.group(1) if match else None


def parse_multipart(body: str, boundary: str):
    if not boundary:
        return {'error': 'No boundary found'}

    boundary_delim = f'--{boundary}'

    sections = body.split(boundary_delim)

    parsed_parts = []

    for part in sections:
        part = part.strip()
        if part.startswith('--'):
            continue

        headers_text, body_text = split_headers_body(part)
        headers = parse_headers(headers_text)

        parsed_parts.append({
            'headers': headers,
            'body': parse_body(body_text, headers)
        })

    return {
        'type': 'multipart',
        'parts': parsed_parts
    }


def parse_headers(header_text: str):
    headers = {}
    current_key = None

    for line in header_text.splitlines():
        if line.startswith((' ', '\t')):
            # continuation line
            if current_key:
                headers[current_key] += ' ' + line.strip()
        else:
            if ':' in line:
                key, value = line.split(':', 1)
                current_key = key.strip()
                headers[current_key] = value.strip()

    return headers


def read_mail(filepath: str):
    with open(filepath, 'rb') as file:
        raw_email = file.read().decode(errors='replace')
        file.close()
    raw_email = raw_email.replace('\r\n', '\n')

    header_text, body_text = split_headers_body(raw_email)

    header = parse_headers(header_text)
    body = parse_body(body_text, header)

    return {'header': header, 'body': body}


def decode_body(body: str, header: dict):
    encoding = header.get('Content-Transfer-Encoding', '').lower()

    if encoding == 'base64':
        clean = body.replace('\n', '').replace('\r', '')
        return base64.b64decode(clean)
    elif encoding == 'quoted-printable':
        return quopri.decodestring(body)
    else:
        return body.encode()


def extract_address(text: str):
    pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    return re.findall(pattern, text)


def get_text_from_parsed(parsed):
    if parsed.get('type') == 'single':
        headers = parsed.get('headers', {})
        content = parsed.get('content', '')
        try:
            decoded = decode_body(content, headers)
            charset = 'utf-8'
            content_type = headers.get('Content-Type', '')
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


def extract_send_ip(headers: dict):
    received_headers = []

    for key, value in headers.items():
        if key.lower() == 'received':
            received_headers.append(value)

    if received_headers:
        first_hop = received_headers[-1]
        pattern = r'\b\d{1,3}(?:\.\d{1,3}){3}\b'
        match = re.search(pattern, first_hop)
        return match.group(0) if match else None
    return None


def extract_urls(body: str):
    pattern = r'https?://[^\s]+|www\.[^\s]+'
    urls = re.findall(pattern, body)
    data = set()
    for url in urls:
        url = re.split(r'[\"\'<>\s]', url)[0]
        url.rstrip('),.')
        data.add(url)
    return data


def extract_auth_res(headers: dict):
    auth = headers.get('Authentication-Results', '')
    return {
        'spf': re.search(r'spf=(\w+)', auth).group(1) if re.search(r'spf=(\w+)', auth) else None,
        'dkim': re.search(r'dkim=(\w+)', auth).group(1) if re.search(r'dkim=(\w+)', auth) else None,
        'dmarc': re.search(r'dmarc=(\w+)', auth).group(1) if re.search(r'dmarc=(\w+)', auth) else None
    }


def extract_domains(mail_data: dict):
    domains = set()

    def extract_domain_from_mail(mail: str):
        return mail.split('@')[1]

    def extract_domain_from_url(url: str):
        url = url.split('://')[1]
        return url.split('/')[0]

    domains.add(extract_domain_from_mail(mail_data.get('from')))
    domains.add(extract_domain_from_mail(mail_data.get('reply_to')))

    if mail_data.get('urls'):
        for url in mail_data.get('urls'):
            domains.add(extract_domain_from_url(url))

    return domains


def extract_data(header: dict, body: str):
    data = {
        'subject': header.get('Subject'),
        'from': extract_address(header.get('From'))[0] if header.get('From', None) else None,
        'to': extract_address(header.get('To'))[0] if header.get('To', None) else None,
        'reply_to': extract_address(header.get('Reply-To'))[0] if header.get('Reply-To', None) else None,
        'sender-ip': extract_send_ip(header),
        'date': header.get('Date') if header.get('From', None) else None,
        'message-id': header.get('Message-Id') if header.get('From', None) else None,
        'auth': extract_auth_res(header),
        'urls': extract_urls(body)
    }

    data.update({'domains': extract_domains(data)})

    return data


def vt_lookup(indicator: str, api_key):
    url = f'https://www.virustotal.com/api/v3/search?query={indicator}'
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json().get('data', {})[0].get('attributes', {}).get('last_analysis_stats', {})
    else:
        raise LookupError(f'Failed to perform vt lookup with status code: {response.status_code}')


def verdict_check(mail_data, api_key):
    verdicts = {}
    if mail_data.get('attachments'):
        files = {}
        for file in mail_data.get('attachments'):
            files.update({file.get('filename'): vt_lookup(file.get('sha256'), api_key)})
        verdicts.update({'files': files})

    if mail_data.get('domains'):
        domains = {}
        for domain in mail_data.get('domains'):
            domains.update({domain: vt_lookup(domain, api_key)})
        verdicts.update({'domains': domains})

    if mail_data.get('sender-ip'):
        verdicts.update({'sender-ip': vt_lookup(mail_data.get('sender-ip'), api_key)})

    if mail_data.get('urls'):
        urls = {}
        for url in mail_data.get('urls'):
            urls.update({url: vt_lookup(url, api_key)})
        verdicts.update({'urls': urls})

    return verdicts


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-f', '--file',
        nargs=1,
        type=str,
        # required=True,
        default='../../Desktop/p.eml',
        help='The path to the .eml to analyse'
    )
    parser.add_argument(
        '-e', '--extract',
        nargs='?',
        const=True,
        default=False,
        help='Extract attachments (optionally specify output directory)'
    )
    parser.add_argument(
        '--vt',
        action='store_true',
        default=False,
        help='Upload indicators to VT for a verdict'
    )
    parser.add_argument(
        '--vt-key',
        type=str,
        default=None,
        help='VirusTotal API key'
    )

    args = parser.parse_args()

    mail = read_mail(args.file)

    body_text = get_text_from_parsed(mail.get('body'))
    data = extract_data(mail.get('header'), body_text)
    data.update({'attachments': extract_attachments(mail.get('body'), args.extract,
                                                    '.' if is_bool(args.extract) else args.extract)})
    if args.vt:
        if args.vt_key is None:
            raise ValueError('API Key not defined. ')
        else:
            verdict_check(data, args.vt_key)
