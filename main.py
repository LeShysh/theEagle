import argparse
import json
import os

from extractor import extract_attachments, extract_data, get_text_from_parsed
from output import human_readable
from parser import read_mail
from virustotal import verdict_check

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
        help='Upload indicators to VT for a verdict (API Key from env: VT_KEY)'
    )
    parser.add_argument(
        '-o', '--output',
        nargs=1,
        type=str,
        choices=['json', 'human-readable'],
        default='human-readable',
        help='Defines the output of the script'
    )
    parser.add_argument(
        '-s', '--sensitivity',
        type=str,
        choices=['high','medium','low'],
        default='high',
        help='VT verdict sensitivity — minimum number of engine hits required (high: 1, medium: 3, low: 5). Default: high'
    )

    args = parser.parse_args()

    mail = read_mail(args.file[0])

    body_text = get_text_from_parsed(mail.get('body'))
    data = extract_data(mail.get('header'), body_text)
    data.update({'attachments': extract_attachments(mail.get('body'), args.extract, '.' if isinstance(args.extract, bool) else args.extract)})

    if args.vt:
        if os.getenv('VT_KEY') is None:
            raise ValueError('API Key not defined as the VT_KEY env. ')
        else:
            match args.sensitivity:
                case 'medium':  sensitivity = 3
                case 'low':     sensitivity = 5
                case _:         sensitivity = 1

            data.update(verdict_check(data, os.getenv('VT_KEY'),sensitivity))

    if args.output == 'human-readable':
        human_readable(data)
    elif args.output[0] == 'json':
        print(json.dumps(data, indent=2))
