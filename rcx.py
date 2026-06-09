"""Library routines for Epson .rcx firmware container files.

An RCX file is a plain-text INI-style header (terminated by a form-feed
byte 0x0C) followed immediately by the raw firmware payload.  The header
declares the sizes of each firmware block in its Z_N sections.
"""

from collections import defaultdict


def parse_rcx(data: bytes):
    """Parse an RCX header.

    Returns
    -------
    header_end : int
        Byte offset of the first payload byte (i.e. position after the
        form-feed terminator that ends the header).
    cfg : defaultdict[str, dict[str, str]]
        Nested dicts of the INI-style configuration.  Keys are section
        names (e.g. ``'Z_1'``); values are dicts mapping option keys to
        their unquoted string values.

    Raises
    ------
    ValueError
        If the data does not conform to the expected RCX format.
    """
    try:
        ff_pos = data.index(b'\f')
    except ValueError:
        raise ValueError(
            'No form-feed (0x0C) terminator found; '
            'this does not look like a valid RCX file'
        )

    header_end = ff_pos + 1

    try:
        header = data[:ff_pos].decode('ascii')
    except UnicodeDecodeError as exc:
        raise ValueError(f'RCX header contains non-ASCII bytes: {exc}')

    lines = header.split('\r\n')

    if len(lines) < 2:
        raise ValueError('RCX header is too short (fewer than 2 lines)')
    if lines[0] != 'RCX':
        raise ValueError(f'Expected first header line "RCX", got {lines[0]!r}')
    if lines[1] != 'SEIKO EPSON EpsonNet Form':
        raise ValueError(f'Unexpected RCX product line: {lines[1]!r}')

    cur_section = ''
    cfg: defaultdict = defaultdict(dict)

    for lineno, line in enumerate(lines[2:], start=3):
        if not line.strip():
            continue

        if line.startswith('[') and line.endswith(']'):
            cur_section = line[1:-1]
            continue

        if '=' not in line:
            raise ValueError(
                f'Line {lineno}: expected key=value assignment, got {line!r}'
            )

        key, value = line.split('=', 1)
        if not (value.startswith('"') and value.endswith('"') and len(value) >= 2):
            raise ValueError(
                f'Line {lineno}: value for key {key!r} must be double-quoted, got {value!r}'
            )
        cfg[cur_section][key] = value[1:-1]

    return header_end, cfg
