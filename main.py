import sys
import base64
import re

def split_headers_body(raw_email: str):
    parts = raw_email.split("\n\n", 1)
    return parts[0], parts[1] if len(parts) > 1 else ""

def parse_body(body: str, headers: dict):
    content_type = headers.get("Content-Type", "")

    if "multipart" in content_type:
        boundary = extract_boundary(content_type)
        return parse_multipart(body, boundary)
    else:
        return {
            "type": "single",
            "content": body.strip()
        }


def extract_boundary(content_type: str):
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            return part.split("=", 1)[1].strip('"')
    return None


def parse_multipart(body: str, boundary: str):
    if not boundary:
        return {"error": "No boundary found"}

    parts = body.split(f"--{boundary}")
    parsed_parts = []

    for part in parts:
        part = part.strip()
        if not part or part == "--":
            continue

        headers_text, body_text = split_headers_body(part)
        headers = parse_headers(headers_text)

        parsed_parts.append({
            "headers": headers,
            "body": parse_body(body_text, headers)
        })

    return {
        "type": "multipart",
        "parts": parsed_parts
    }

def parse_headers(header_text: str):
    headers = {}
    current_key = None

    for line in header_text.splitlines():
        if line.startswith((" ", "\t")):
            # continuation line
            if current_key:
                headers[current_key] += " " + line.strip()
        else:
            if ":" in line:
                key, value = line.split(":", 1)
                current_key = key.strip()
                headers[current_key] = value.strip()

    return headers

def read_mail(filepath: str):
    with open(filepath, 'r') as file:
        raw_email = file.read()
        file.close()
    parts = raw_email.split("\n\n", 1)

    header = parse_headers(parts[0])
    body = parse_body(parts[1], header)

    return {'header':header, 'body':body}

def decode_body(body: dict):
    encoding = body.get('parts',{})[0].get('body',[]).get('parts',[])[0].get('headers',{}).get('Content-Transfer-Encoding','')
    content = body.get('parts', {})[0].get('body', []).get('parts',[])[0].get('body',{}).get('content','')
    if encoding == 'base64':
        decoded_content = base64.b64decode(content).decode('ascii', errors='ignore')
    else:
        raise ValueError(f'Unknown encoding: {encoding}')


    return decoded_content

def check_spf(header: dict):
    pass

def check_dkim(header: dict):
    pass

def check_dmarc(header: dict):
    pass

def extract_address(text:str):
    pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    return re.findall(pattern, text)

def extract_indicators(header:dict, body:str):
    data = {}

    print (header)

    data.update({'subject':header.get('Subject')})
    data.update({'from': extract_address(header.get('From'))[0]})
    data.update({'to': extract_address(header.get('To'))[0]})
    data.update({'reply_to': extract_address(header.get('Reply-To'))[0]})

    pattern = r'https?://[^\s]+|www\.[^\s]+'
    data.update({'url': re.findall(pattern,body)})


    return data

def analyse_urls():
    pass

def analyse_attachment():
    pass


if __name__ == '__main__':
    #if len(sys.argv) > 2:
    #    raise ValueError('No email provided as an argument')
    #filepath = sys.argv[1]
    filepath = '../../Desktop/l.eml'
    mail = read_mail(filepath)
    body = decode_body(mail.get('body'))
    ioc = extract_indicators(mail.get('header'), body)
    print(ioc)