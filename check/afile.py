#!/usr/bin/env python3
"""Read-only A249110 documentary table audit. Project author: Carlo Corti.

Prepared by Luna. Python integer trial division and isqrt; no producer calls.
This checks saved witnesses, not completeness of the negative search interval.
"""
from pathlib import Path
import argparse
import hashlib
import json
import math
import re


def need(condition, message):
    if not condition:
        raise ValueError(message)


def records(path):
    raw = path.read_bytes()
    need(raw.endswith(b'\n\n') and not raw.endswith(b'\n\n\n'),
         'expected exactly one final empty record: ' + str(path))
    need(b'\r' not in raw and b'\0' not in raw, 'invalid framing: ' + str(path))
    text = raw.decode('ascii')
    data = []
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        need(re.fullmatch(r'(0|[1-9][0-9]*)( (0|[1-9][0-9]*))*', line) is not None,
             'noncanonical decimal row: ' + str(path))
        data.append(list(map(int, line.split(' '))))
    need(bool(data), 'empty data: ' + str(path))
    return raw, data


def derivative(n):
    if n < 2:
        return 0
    remaining, candidate, result = n, 2, 0
    while candidate * candidate <= remaining:
        exponent = 0
        while remaining % candidate == 0:
            remaining //= candidate
            exponent += 1
        result += exponent * (n // candidate)
        candidate = 3 if candidate == 2 else candidate + 2
    if remaining > 1:
        result += n // remaining
    return result


def audit(bfile, afile):
    braw, baseline = records(bfile)
    araw, rows = records(afile)
    need(len(baseline) == len(rows), 'a/b row cardinality mismatch')
    prior = 1
    for index, (base, row) in enumerate(zip(baseline, rows), 1):
        need(len(base) == 2 and base[0] == index and base[1] > prior,
             'b-file indices/order')
        need(len(row) == 11 and row[:2] == base, 'a/b index/value correspondence')
        for left, right in zip(row[1:9], row[2:10]):
            need(derivative(left) == right, 'arithmetic derivative mismatch at index ' + str(index))
        total = sum(value * value for value in row[1:10])
        need(row[10] > 0 and math.isqrt(total) == row[10] and row[10] ** 2 == total,
             'square/root mismatch at index ' + str(index))
        prior = base[1]
    return {'status': 'PASS', 'rows': len(rows), 'columns': 11,
            'derivative_identities': 8 * len(rows), 'square_identities': len(rows),
            'bfile_sha256': hashlib.sha256(braw).hexdigest(),
            'afile_sha256': hashlib.sha256(araw).hexdigest(), 'afile_bytes': len(araw),
            'framing': 'ASCII, LF, exactly one terminal empty record',
            'independent_negative_enumeration': False,
            'method': 'Complete trial division and Python integer isqrt; table and b-file correspondence.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bfile', type=Path)
    parser.add_argument('afile', type=Path)
    args = parser.parse_args()
    try:
        result = audit(args.bfile, args.afile)
    except (OSError, ValueError, UnicodeError) as error:
        print('REFUSE:', error)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
