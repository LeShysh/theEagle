import hashlib
import sys
import base64
import re
import urllib.parse
import quopri


def split_headers_body(raw_email: str):
    raw_email = raw_email.lstrip('\n')
    parts = raw_email.split("\n\n", 1)
    return parts[0], parts[1] if len(parts) > 1 else ''

def parse_body(body: str, headers: dict):
    content_type = headers.get('Content-Type', '')

    if 'multipart' in content_type:
        boundary = extract_boundary(content_type)
        res = parse_multipart(body, boundary)
        res.update({'headers':headers})
        return res
    else:
        return {
            'type': 'single',
            'headers':headers,
            'content': body.strip()
        }


def is_attachment(headers: dict):
    cd = headers.get('Content-Disposition','')
    return 'attachment' in cd.lower()

def get_filename(headers: dict):
    cd = headers.get('Content-Disposition','')

    for part in cd.split(';'):
        part =part.strip()

        if part.startswith('filename*='):
            encoded = part.split('=',1)[1]
            _, _, value = encoded.partition("''")
            return urllib.parse.unquote(value)

        elif part.startswith('filename='):
            return part.split('=', 1)[1].strip('"')

    return None

def extract_attachments(parsed: dict, extract:bool=True, save_path:str='.'):
    attachments = []
    if parsed.get('type') == 'multipart':
        for part in parsed.get('parts'):
            headers = part.get('headers')
            body = part.get('body')

            if is_attachment(headers):
                filename = get_filename(headers)

                if body.get('type') == 'single':
                    data = decode_body(body.get('content'),headers)

                    fileinfo = {
                        'filename': filename,
                        'sha256': hashlib.sha256(data).hexdigest(),
                        'md5': hashlib.md5(data).hexdigest(),
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

    return {'header':header, 'body':body}

def decode_body(body: str, header:dict):
    encoding = header.get('Content-Transfer-Encoding','').lower()

    if encoding == 'base64':
        clean = body.replace('\n','').replace('\r','')
        return base64.b64decode(clean)
    elif encoding == 'quoted-printable':
        return quopri.decodestring(body)
    else:
        return body.encode()


def extract_address(text:str):
    pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    return re.findall(pattern, text)

def extract_indicators(header:dict, body:str):
    data = {}

    data.update({'subject':header.get('Subject')})
    data.update({'from': extract_address(header.get('From'))[0] if header.get('From',None) else None})
    data.update({'to': extract_address(header.get('To'))[0] if header.get('To',None) else None})
    data.update({'reply_to': extract_address(header.get('Reply-To'))[0] if header.get('Reply-To',None) else None})

    pattern = r'https?://[^\s]+|www\.[^\s]+'
    data.update({'url': re.findall(pattern,body)})
    return data

def get_text_from_paresd(parsed):
    if parsed.get('type') == 'single':
        headers = parsed.get('headers',{})
        content = parsed.get('content','')
        try:
            decoded = decode_body(content,headers)
            charset = 'utf-8'
            content_type = headers.get('Content-Type','')
            m = re.search(r'charset=([^\s;]+)', content_type, re.IGNORECASE)
            if m:
                charset = m.group(1).strip('"').lower()
            return decoded.decode(charset, errors='replace')
        except Exception:
            return content
        return parsed.get('content','')
    elif parsed.get('type') == 'multipart':
        text = ''
        for part in parsed.get('parts', []):
            text += get_text_from_paresd(part.get('body',{})) + '\n'
        return text
    return ''



if __name__ == '__main__':
    #if len(sys.argv) > 2:
    #    raise ValueError('No email provided as an argument')
    #filepath = sys.argv[1]
    filepath = '../../Desktop/x.eml'
    mail = read_mail(filepath)
    attachments = extract_attachments(mail.get('body'))
    body_text = get_text_from_paresd(mail.get('body'))
    ioc = extract_indicators(mail.get('header'), body_text)
    print(ioc)
    print(attachments)
