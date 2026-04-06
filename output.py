from rich.console import Console
from rich.pretty import Pretty
from rich.table import Table


def color_ioc(ioc):
    """Wrap an IOC value in a Rich color tag based on its verdict (red=malicious, yellow=suspicious, green=benign, blue=unknown)."""
    if isinstance(ioc, dict):
        ioc = next(iter(ioc.items()))
        return color_ioc(ioc)
    elif isinstance(ioc, tuple):
        match ioc[1]:
            case 'malicious':   return f'[red]{ioc[0]}[/]'
            case 'suspicious':  return f'[yellow]{ioc[0]}[/]'
            case 'benign':      return f'[green]{ioc[0]}[/]'
            case _:             return f'[blue]{ioc[0]}[/]'
    else:
        return f'[blue]{ioc}[/]'

def defang(url):
    """Defang the provided URL to avoid accidental clicks"""
    return url.replace('https://', 'hxxps://').replace('http://', 'hxxp://').replace('.', '[.]')

def attachment_verdict(attachment: dict) -> str:
    verdict = attachment.get('verdict', 'unknown')
    if attachment.get('mime_mismatch'):
        if verdict in ('benign', 'unknown'):
            verdict = 'suspicious'
    return verdict


def human_readable(mail_data):
    """Render the mail data dict as a formatted Rich table in the terminal."""
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
                if value:
                    lines = []
                    for f in value:
                        name = f.get('filename', '?')
                        verdict = attachment_verdict(f)
                        if f.get('mime_mismatch'):
                            name += ' (Type mismatch)'
                        lines.append(color_ioc((name, verdict)))
                    rendered = '\n'.join(lines)
                else:
                    rendered = '-'
            elif key == 'urls':
                urls = [defang(url) for url in value]
                start = '\n'.join(urls[:5])
                rest = f'\n... (+{len(urls) - 5} more)' if len(urls) > 5 else ''
                rendered = start + rest
            elif key == 'received_chain':
                lines = []
                for i, hop in enumerate(value):
                    ip = hop.get('from_ip', '?')
                    host = hop.get('from_host', '')
                    by = hop.get('by', '?')
                    proto = hop.get('with', '')
                    time = hop.get('time', '')[:25]  # trim long timezone strings
                    lines.append(f"[dim]{i + 1}.[/] {ip} [dim]({host})[/] → {by} [dim]{proto} {time}[/]")
                rendered = '\n'.join(lines) if lines else '-'
            else:
                rendered = '\n'.join(map(str, value)) if value else '-'
            table.add_row(key, rendered)
        else:
            if key == 'sender-ip' and value is not None:
                value = color_ioc(value)
            rendered = str(value)
            table.add_row(key, rendered)
    console.print(table)
