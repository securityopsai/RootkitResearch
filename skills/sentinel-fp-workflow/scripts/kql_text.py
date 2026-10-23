"""Small lexical helper for local lint/testing, not a KQL parser or binder."""

import re


def segments(text):
    """Yield (kind, start, end), preserving offsets and all original text.

    Recognizes ordinary/escaped, verbatim, and triple-backtick strings, plus
    line/block comments. Prefixes such as h and @ remain untouched.
    Unterminated strings/comments are errors instead of being rewritten.
    """
    i = code_start = 0
    while i < len(text):
        start = i
        if text.startswith('//', i):
            end = text.find('\n', i)
            end = len(text) if end < 0 else end
            kind = 'comment'
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            if end < 0:
                raise ValueError('Unterminated block comment')
            end += 2
            kind = 'comment'
        elif text.startswith('```', i):
            end = text.find('```', i + 3)
            if end < 0:
                raise ValueError('Unterminated multiline string')
            end += 3
            kind = 'string'
        elif text[i] in ('"', "'"):
            quote = text[i]
            verbatim = i > 0 and text[i - 1] == '@'
            if i > 1 and text[i - 2:i].lower() == '@h':
                verbatim = True
            end = i + 1
            while end < len(text):
                if not verbatim and text[end] == '\\':
                    end += 2
                    continue
                if text[end] == quote:
                    if verbatim and end + 1 < len(text) and text[end + 1] == quote:
                        end += 2
                        continue
                    end += 1
                    break
                end += 1
            else:
                raise ValueError('Unterminated string literal')
            if end > len(text):
                raise ValueError('Unterminated string escape')
            kind = 'string'
        else:
            i += 1
            continue
        if code_start < start:
            yield 'code', code_start, start
        yield kind, start, end
        i = code_start = end
    if code_start < len(text):
        yield 'code', code_start, len(text)


def views(text):
    """Return equal-length (code-only, comments-masked, comments-only) views."""
    code, uncommented, comments = list(text), list(text), ['\n' if c == '\n' else ' ' for c in text]
    for kind, start, end in segments(text):
        if kind == 'code':
            continue
        for i in range(start, end):
            code[i] = '\n' if text[i] == '\n' else ' '
            if kind == 'comment':
                uncommented[i] = code[i]
                comments[i] = text[i]
    return ''.join(code), ''.join(uncommented), ''.join(comments)


CALL = re.compile(r'(?<![\w.])(?P<name>now|ago|ingestion_time)\s*\(')
CLOCK_NAME = '__fixture_now'
INGESTION_COLUMN = '__ingestion_time'


def time_calls(text):
    return {m.group('name') for m in CALL.finditer(views(text)[0])}


def rewrite_time_calls(text):
    """Rewrite code only. Callers validate fixture clock and ingestion columns."""
    code = views(text)[0]

    def rewrite(start, end):
        out, cursor = [], start
        while cursor < end:
            match = CALL.search(code, cursor, end)
            if match is None:
                out.append(text[cursor:end])
                break
            depth, close = 1, match.end()
            while close < end and depth:
                if code[close] == '(':
                    depth += 1
                elif code[close] == ')':
                    depth -= 1
                close += 1
            if depth:
                raise ValueError('Unbalanced time-function parentheses')
            inner_start, inner_end = match.end(), close - 1
            name = match.group('name')
            arg_code = code[inner_start:inner_end].strip()
            if name == 'ingestion_time':
                if arg_code:
                    raise ValueError('ingestion_time() takes no arguments')
                replacement = '(' + text[inner_start:inner_end] + INGESTION_COLUMN + ')'
            elif not arg_code:
                if name == 'ago':
                    raise ValueError('ago() requires a timespan')
                replacement = '(' + text[inner_start:inner_end] + CLOCK_NAME + ')'
            else:
                arg = rewrite(inner_start, inner_end)
                operator = '+' if name == 'now' else '-'
                replacement = f'({CLOCK_NAME} {operator} ({arg}))'
            out.extend((text[cursor:match.start()], replacement))
            cursor = close
        return ''.join(out)

    return rewrite(0, len(text))
