#!/usr/bin/env python3
"""Finite exact manuscript checks; no search of an input interval or producer call.

Carlo Corti is the project author; prepared by Luna. Python 3.11+ stdlib.
Reads the nine saved tuples, sealed manifest rows, and two depth examples.
Prints JSON only. Run from any directory: python3 -B -O paper/analyze.py.
"""
from pathlib import Path
from fractions import Fraction
from functools import reduce
import hashlib
import json
import math

ROOT = Path(__file__).resolve().parents[1]


def need(ok, message):
    if not ok:
        raise ValueError(message)


def factor(n):
    need(n >= 0, 'nonnegative integer required')
    rem, p, out = n, 2, []
    while p <= rem // p:
        e = 0
        while rem % p == 0:
            rem //= p
            e += 1
        if e:
            out.append((p, e))
        p = 3 if p == 2 else p + 2
    if rem > 1:
        out.append((rem, 1))
    if n > 1:
        need(math.prod(p ** e for p, e in out) == n, 'factor product')
    return out


def derivative(n):
    return sum(e * (n // p) for p, e in factor(n)) if n > 1 else 0


def chain(n, depth=8):
    xs = [n]
    for _ in range(depth):
        xs.append(derivative(xs[-1]))
    return xs


def majorant(u):
    if u < 2:
        return 0
    values = []
    for a in range(u.bit_length()):
        m = u // (1 << a)
        m -= 1 - m % 2
        k, t = 0, m
        while t >= 3:
            t //= 3
            k += 1
        values.append((a * (1 << (a - 1)) * m if a else 0)
                      + (1 << a) * (m * k // 3))
    return max(values)


def rate_core(lam):
    need(lam >= 0, 'negative rate')
    a, b = lam.numerator, lam.denominator
    fs = factor(b)
    need(all(e == 1 for _, e in fs), 'nonsquarefree denominator')
    residues = [(p, a * pow(b // p, -1, p) % p) for p, _ in fs]
    alpha = sum((Fraction(r, p) for p, r in residues), Fraction(0))
    k = lam - alpha
    need(k.denominator == 1, 'nonintegral residual rate')
    return {'rate': str(lam), 'residues': residues,
            'core': math.prod(p ** r for p, r in residues),
            'core_rate': str(alpha), 'k': int(k),
            'integer_scale_exists': k >= 0}


def main():
    a_path, b_path = ROOT / 'data/a249110.txt', ROOT / 'data/b249110.txt'
    araw, braw = a_path.read_bytes(), b_path.read_bytes()
    for raw in (araw, braw):
        need(raw.endswith(b'\n\n') and not raw.endswith(b'\n\n\n'), 'final blank record')
    rows = [list(map(int, s.split())) for s in araw.decode('ascii').splitlines()
            if s and not s.startswith('#')]
    brows = [list(map(int, s.split())) for s in braw.decode('ascii').splitlines() if s]
    need(len(rows) == len(brows) == 9, 'nine canonical terms')
    forms, reports = {}, []
    for i, (row, base) in enumerate(zip(rows, brows), 1):
        need(len(row) == 11 and row[:2] == base and row[0] == i, 'a/b semantics')
        xs, r = row[1:10], row[10]
        need(xs == chain(xs[0]), 'saved chain')
        need(sum(x * x for x in xs) == r * r and r > 0, 'saved square')
        g = reduce(math.gcd, xs + [r])
        u = tuple(x // g for x in xs + [r])
        need(reduce(math.gcd, u) == 1, 'primitive gcd includes root')
        lam = Fraction(u[1] - derivative(u[0]), u[0])
        need(all(u[j + 1] == derivative(u[j]) + lam * u[j] for j in range(8)),
             'generalized transitions including zero')
        need(Fraction(derivative(g), g) == lam, 'observed scale rate')
        need(sum(x * x for x in u[:9]) == u[9] ** 2, 'primitive square')
        forms.setdefault(u, []).append(i)
        q, depths = 0, []
        for j, x in enumerate(xs):
            q += x * x
            if j and math.isqrt(q) ** 2 == q:
                depths.append(j)
        reports.append({'index': i, 'n': xs[0], 'root': r, 'gcd': g,
                        'primitive': u, 'rate': str(lam),
                        'scale_core': rate_core(lam), 'square_depths_1_to_8': depths,
                        'primitive_factors_0_to_7': [factor(x) for x in u[:8]],
                        'primitive_derivatives_0_to_7': [derivative(x) for x in u[:8]],
                        'sum_of_squares': sum(x*x for x in xs)})
    coverage, previous = [], None
    hits = []
    for run, seals in [('first', 2), ('5E10', 29), ('22E9', 3)]:
        lines = (ROOT / 'runs' / run / 'man.tsv').read_text().splitlines()
        need(len(lines) == seals + 2, 'committed manifest cardinality')
        for j, line in enumerate(lines[2:]):
            c = line.split('\t'); sid, lo, hi, blocks = map(int, c[:4])
            need(sid == j and (previous is None or lo == previous + 1), 'ordered join')
            state = ROOT / 'runs' / run / f's{sid:03}.tsv'
            sha = hashlib.sha256(state.read_bytes()).hexdigest()
            need(sha == c[4] and (state.with_suffix('.sha')).read_text() == sha+'\n',
                 'sealed state identity')
            previous = hi
            coverage.append({'run': run, 'low': lo, 'high': hi, 'blocks': blocks,
                             'saved_ns': int(c[5]), 'fallbacks': int(c[6]), 'hits': int(c[7])})
        for line in (ROOT / 'runs' / run / 'hits.tsv').read_text().splitlines()[2:]:
            hits.append(list(map(int, line.split('\t'))))
    need(hits == [row[1:] for row in rows[5:]], 'campaign-positive/table correspondence')
    need(coverage[0]['low'] == 823544 and previous == 22000000000, 'coverage endpoints')
    bounds = [50000000000]
    for _ in range(8):
        bounds.append(majorant(bounds[-1]))
    qmax = sum(x*x for x in bounds)
    c = reports[6]['primitive'][0]
    need(reports[6]['primitive'] == reports[7]['primitive'], 'handoff pair')
    need(c * 4 == rows[6][1] and c * 27 == rows[7][1], 'family specializations')
    examples = {str(n): {'chain': chain(n), 'Q3': sum(x*x for x in chain(n, 3)),
                         'Q4': sum(x*x for x in chain(n, 4))} for n in (4, 19164)}
    result = {'status': 'PASS', 'scope': 'finite saved witnesses and records; no negative enumeration',
              'python': __import__('sys').version, 'rows': reports,
              'forms': [{'primitive': u, 'indices': ix} for u, ix in forms.items()],
              'form_count': len(forms), 'coverage': coverage,
              'totals': {k: sum(r[k] for r in coverage) for k in ('blocks','saved_ns','fallbacks','hits')},
              'classified_inputs': sum(r['high']-r['low']+1 for r in coverage),
              'majorants_5E10': bounds, 'majorant_bits': [x.bit_length() for x in bounds],
              'Qmax': qmax, 'Qmax_bits': qmax.bit_length(), 'Rmax': math.isqrt(qmax),
              'rate_examples': [rate_core(Fraction(1,6)), rate_core(Fraction(1,2)),
                                rate_core(Fraction(3,2)), rate_core(Fraction(0))],
              'next_family_witness': c * 5**5, 'stationary_upper_witness': 11**11,
              'depth_examples': examples}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
