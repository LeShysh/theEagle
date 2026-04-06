import argparse
import base64
import json
import os
import quopri
import re
import urllib.parse
from hashlib import sha256, md5

import requests
from rich.console import Console
from rich.pretty import Pretty
from rich.table import Table


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

            attachments.extend(extract_attachments(body, extract, save_path))

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
                if isinstance(headers[current_key], list):
                    headers[current_key][-1] += ' ' + line.strip()
                else:
                    headers[current_key] += ' ' + line.strip()
        else:
            if ':' in line:
                key, value = line.split(':', 1)
                current_key = key.strip().lower()
                if current_key in headers:
                    existing = headers[current_key]
                    if isinstance(existing, list):
                        existing.append(value.strip())
                    else:
                        headers[current_key] = [existing, value.strip()]
                else:
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
    pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+'
    return re.findall(pattern, text)[0]


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
    pattern = r'https?://[^\s]+|www\.[^\s]+'
    urls = re.findall(pattern, body)
    data = set()
    for url in urls:
        url = re.split(r'[\"\'<>\s]', url)[0]
        url.rstrip('),.')
        data.add(url)
    return list(data)


def extract_auth_res(headers: dict):
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
    domains = set()

    def extract_domain_from_mail(mail: str):
        return mail.split('@')[1]

    def extract_domain_from_url(url: str):
        url = url.split('://')[1]
        return url.split('/')[0]

    domains.add(extract_domain_from_mail(mail_data.get('from')))
    if mail_data.get('reply_to') is not None:
        domains.add(extract_domain_from_mail(mail_data.get('reply_to')))

    if mail_data.get('urls'):
        for url in mail_data.get('urls'):
            domains.add(extract_domain_from_url(url))

    return list(domains)


def extract_data(header: dict, body: str):
    mail_data = {
        'subject': header.get('subject'),
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

def vt_verdict(verdict:dict):
    if verdict.get('malicious') > 0:
        return 'malicious'
    elif verdict.get('suspicious') > 0:
        return 'suspicious'
    elif verdict.get('harmless') > 0:
        return 'benign'
    else:
        return 'unknown'


def vt_lookup(indicator: str, api_key):
    url = f'https://www.virustotal.com/api/v3/search?query={indicator}'
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        if len(response.json().get('data', {})) == 0:
            return 'unknown'
        res = response.json().get('data', {})[0].get('attributes', {}).get('last_analysis_stats', {})
        return vt_verdict(res)
    else:
        raise LookupError(f'Failed to perform vt lookup with status code: {response.status_code}')

def verdict_check(mail_data, api_key):
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
        verdicts.update({'sender-ip': {mail_data.get('sender-ip'):vt_lookup(mail_data.get('sender-ip'), api_key)}})

    return verdicts

def color_ioc(ioc):
    if isinstance(ioc, dict):
        match ioc.values()[0]:
            case 'malicious':
                return f'[red]{ioc.items()[0]}[/]'
            case 'suspicious':
                return f'[yellow]{ioc.items()[0]}[/]'
            case 'benign':
                return f'[green]{ioc.items()[0]}[/]'
            case _:
                return f'[white]{ioc.items()[0]}[/]'
    elif isinstance(ioc, tuple):
        if 'malicious' == ioc[1]:
            return f'[red]{ioc[0]}[/]'
        elif 'suspicious' == ioc[1]:
            return f'[yellow]{ioc[0]}[/]'
        elif 'benign' == ioc[1]:
            return f'[green]{ioc[0]}[/]'
        else:
            return f'[blue]{ioc[0]}[/]'
    else:
        return f'[blue]{ioc}[/]'


def human_readable(mail_data):
    console = Console()
    table = Table(title='  Mail Header', show_lines=True)
    table.add_column('Field', style='cyan', no_wrap=True)
    table.add_column('Value', style='white', no_wrap=True)

    for key, value in mail_data.items():
        if isinstance(value, dict):
            if key == 'auth':
                for auth, status in dict(value).items():
                    rendered = '-' if status is None else status
                    match rendered.lower():
                        case 'pass':
                            rendered = '[green]pass[/]'
                        case 'none':
                            rendered = '[yellow]-[/]'
                        case _:
                            rendered = f'[red]{rendered.lower()}[/]'

                    table.add_row(auth, rendered)
            elif key == 'domains':
                domains = []
                for entry in value.items():
                    domains.append(color_ioc(entry))
                rendered = '\n'.join(domains)
                table.add_row(key, rendered)
            elif key == 'attachments':
                files = []
                for entry in value.items():
                    files.append(color_ioc(entry))
                rendered = '\n'.join(files)
                table.add_row(key, rendered)
            elif key == 'sender-ip':
                for entry in value.items():
                    table.add_row(key, color_ioc(entry))
            else:
                rendered = Pretty(value, expand_all=True)
                table.add_row(key, rendered)
        elif isinstance(value, set):
            rendered = '\n'.join((sorted(value)))
            table.add_row(key, rendered)
        elif isinstance(value, list):
            if key == 'attachments':
                if len(value) > 0:
                    files = [file.get('filename') for file in value]
                    rendered = '\n'.join(files)
                else:
                    rendered = '-'
            elif key == 'urls':
                urls = list(value)
                start = '\n'.join(urls[:5])
                rest = f'\n... (+{len(urls) - 5} more)' if len(urls) > 5 else ''
                rendered = start + rest
            else:
                rendered = '\n'.join(map(str, value)) if value else '-'
            table.add_row(key, rendered)
        else:
            if key == 'sender-ip' and value is not None:
                value = color_ioc(value)
            rendered = str(value)
            table.add_row(key, rendered)
    console.print(table)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-f', '--file',
        nargs=1,
        type=str,
        required=True,
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
    parser.add_argument(
        '-o', '--output',
        nargs=1,
        type=str,
        choices=['json', 'human-readable'],
        default='human-readable',
        help='Defines the output of the script'
    )

    args = parser.parse_args()

    mail = read_mail(args.file[0])

    body_text = get_text_from_parsed(mail.get('body'))
    data = extract_data(mail.get('header'), body_text)
    data.update({'attachments': extract_attachments(mail.get('body'), args.extract,'.' if isinstance(args.extract, bool) else args.extract)})

    if args.vt:
        if os.getenv('VT_KEY') is None:
            raise ValueError('API Key not defined as the VT_KEY env. ')
        else:
            data.update(verdict_check(data, os.getenv('VT_KEY')))

    if args.output == 'human-readable':
        human_readable(data)
    elif args.output[0] == 'json':
        print(json.dumps(data, indent=2))
