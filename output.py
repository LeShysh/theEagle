from rich.console import Console
from rich.pretty import Pretty
from rich.table import Table


def color_ioc(ioc):
    """Wrap an IOC value in a Rich colour tag based on its verdict (red=malicious, yellow=suspicious, green=benign, blue=unknown)."""
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
