import base64
import quopri
import re
import urllib.parse


def split_headers_body(raw_email: str):
    """Split a raw email string into a (headers, body) tuple on the first blank line."""
    raw_email = raw_email.lstrip('\n')
    parts = raw_email.split("\n\n", 1)
    return parts[0], parts[1] if len(parts) > 1 else ''


def parse_headers(header_text: str):
    """
    Parse raw header text into a dict.
    Folded (multi-line) header values are joined, and duplicate keys are collected into a list.
    """
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


def extract_boundary(content_type: str):
    """Parse the boundary parameter out of a multipart Content-Type header value."""
    pattern = r'boundary="?([^";]+)"?'
    match = re.search(pattern, content_type, re.IGNORECASE)
    return match.group(1) if match else None


def decode_body(body: str, header: dict):
    """Decode a body string according to its Content-Transfer-Encoding (base64, quoted-printable, or plain)."""
    encoding = header.get('content-transfer-encoding', '').lower()

    if encoding == 'base64':
        clean = body.replace('\n', '').replace('\r', '')
        return base64.b64decode(clean)
    elif encoding == 'quoted-printable':
        return quopri.decodestring(body)
    else:
        return body.encode()


def is_attachment(headers: dict):
    """Return True if the Content-Disposition header marks this part as an attachment."""
    cd = headers.get('content-disposition', '')
    return 'attachment' in cd.lower()


def get_filename(headers: dict):
    """Extract the filename from a Content-Disposition header, handling RFC 5987 encoding."""
    cd = headers.get('content-disposition', '')

    for part in cd.split(';'):
        part = part.strip()

        if part.startswith('filename*='):
            encoded = part.split('=', 1)[1]
            _, _, value = encoded.partition("''")
            return urllib.parse.unquote(value)

        elif part.startswith('filename='):
            return part.split('=', 1)[1].strip('"')

    return None


def parse_body(body: str, headers: dict):
    """Parse an email body into a structured dict, handling multipart and single-part messages."""
    content_type = headers.get('content-type', '')

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


def parse_multipart(body: str, boundary: str):
    """Split a multipart body on its boundary and recursively parse each section."""
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


def read_mail(filepath: str):
    """Read an .eml file from disk and return a dict with 'header' and 'body' keys."""
    with open(filepath, 'rb') as file:
        raw_email = file.read().decode(errors='replace')
    raw_email = raw_email.replace('\r\n', '\n')

    header_text, body_text = split_headers_body(raw_email)
    header = parse_headers(header_text)
    body = parse_body(body_text, header)

    return {'header': header, 'body': body}

def decode_rfc2047(text: str) -> str:
    """Decode RFC 2047 encoded words in a header value, returning a plain Unicode string."""
    pattern = r'=\?([^?]+)\?([BbQq])\?([^?]*)\?='

    def decode_word(match):
        charset, encoding, encoded_text = match.group(1), match.group(2), match.group(3)
        if encoding.upper() == 'B':
            data = base64.b64decode(encoded_text)
        else:  # Q
            data = quopri.decodestring(encoded_text.replace('_', ' '))
        return data.decode(charset, errors='replace')

    # Remove whitespace between consecutive encoded words before decoding
    text = re.sub(r'\?=\s+=\?', '?==?', text)
    return re.sub(pattern, decode_word, text)
