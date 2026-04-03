import sys
import eml_parser
import json
import datetime

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

def readmail(filepath):
    with open(filepath, 'r') as file:
        raw_email = file.read()
        file.close()
    parts = raw_email.split("\n\n", 1)

    header = parse_headers(parts[0])
    body = parse_body(parts[1], header)

    return {'header':header, 'body':body}

def checkspf():
    pass

def checkdkim():
    pass

def checkdmarc():
    pass

def extractindicators():
    pass

def analyseurls():
    pass

def analyseattachment():
    pass


if __name__ == '__main__':
    #if len(sys.argv) > 2:
    #    raise ValueError('No email provided as an the argument')
    #filepath = sys.argv[1]
    filepath = '../../Desktop/l.eml'
    mail = readmail(filepath)
