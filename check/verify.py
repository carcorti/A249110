#!/usr/bin/env python3
"""Portable, fail-closed A249110 package checks. Author: Carlo Corti.

Prepared by Luna. Default: retained data/records/finite arithmetic, Python stdlib.
native: also a fresh public build and 259 temporary candidate classifications.
dev: additionally rebuild/replay the original quick and wide development suites.
restore DEST: restore indexed historical paths to a new directory outside payload.
No mode repeats the official negative census. All generated work is temporary.
"""
from pathlib import Path, PurePosixPath
import argparse
import difflib
import hashlib
import importlib.util
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TITLE = ('Nine-Square Arithmetic-Derivative Tuples: An Extension of OEIS '
         'A249110 and Their Scaling Structure')
DOI = '10.5281/zenodo.23695423'
CALLS = []

def need(ok, message):
    if not ok:
        raise ValueError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def safe(name):
    need(isinstance(name, str) and name and '\\' not in name, 'invalid path')
    p = PurePosixPath(name)
    need(not p.is_absolute() and all(x not in ('', '.', '..') for x in name.split('/')),
         'unsafe path: ' + name)
    return p

def plain_json(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            need(k not in result, 'duplicate JSON key: ' + k)
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs)

def command(args, expected=0, timeout=90):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    p = subprocess.run([str(x) for x in args], capture_output=True, text=True,
                       timeout=timeout, env=env)
    CALLS.append({'argv':[str(x) for x in args], 'returncode':p.returncode,
                  'stdout':p.stdout, 'stderr':p.stderr})
    need(p.returncode == expected, 'command failed: ' + json.dumps(CALLS[-1]))
    return p.stdout

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def integrity():
    manifest = (ROOT/'checks.sha256').read_text(encoding='ascii')
    expected = {}
    for line in manifest.splitlines():
        m = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        need(m is not None, 'checksum manifest grammar')
        h, name = m.groups()
        safe(name)
        need(name != 'checks.sha256' and name not in expected, 'manifest duplicate/self')
        expected[name] = h
    need(expected and list(expected) == sorted(expected), 'manifest order/empty')
    actual = set()
    actual_dirs = set()
    for current, dirs, files in os.walk(ROOT, followlinks=False):
        base = Path(current)
        if base == ROOT and '.git' in dirs:
            need(not (base/'.git').is_symlink(), 'symlink git metadata')
            dirs.remove('.git')
        for name in dirs + files:
            p = base/name
            need(not p.is_symlink(), 'symlink payload: ' + str(p))
        actual_dirs.update((base/name).relative_to(ROOT).as_posix() for name in dirs)
        for name in files:
            p = base/name
            rel = p.relative_to(ROOT).as_posix()
            need(p.is_file(), 'nonregular file: ' + rel)
            if rel in ('checks.sha256', '.git', 'src/a249110'):
                continue  # manifest, root Git metadata, specifically generated build
            actual.add(rel)
    need(actual == set(expected), 'missing/unexpected payload: '+str(actual ^ set(expected)))
    expected_dirs = {parent.as_posix() for name in expected
                     for parent in PurePosixPath(name).parents if parent.as_posix() != '.'}
    need(actual_dirs == expected_dirs, 'unexpected directory layout')
    for name, h in expected.items():
        need(digest((ROOT/name).read_bytes()) == h, 'changed file: '+name)
    return expected

def metadata(index):
    need(index['schema'] == 1 and index['author'] == 'Carlo Corti', 'index identity/schema')
    cff = (ROOT/'CITATION.cff').read_text()
    # Full YAML/CFF schema validation is a preparation check; these are the
    # runtime cross-file invariants for the already-frozen metadata bytes.
    need('cff-version: 1.2.0\n' in cff and 'type: software\n' in cff, 'CFF format')
    need('family-names: Corti' in cff and 'given-names: Carlo' in cff, 'CFF author')
    need(cff.count(DOI) == 4 and TITLE in cff and 'version: v1.0.1\n' in cff, 'CFF title/version/DOIs')
    need('https://github.com/carcorti/A249110' in cff, 'CFF repository')
    need('Copyright (c) 2026 Carlo Corti' in (ROOT/'LICENSE').read_text(), 'license identity')
    tex = (ROOT/'paper/A249110.tex').read_text()
    need('\\author{Carlo Corti\\\\Independent researcher\\\\' in tex, 'TeX author')
    need('carlo.corti@outlook.com' in tex and '\\date{October 2026}' in tex, 'TeX email/date')
    need('https://doi.org/'+DOI in tex, 'TeX designated series DOI')
    need(not re.search(r'\\(?:input|include|bibliography|addbibresource)\b', tex), 'monolithic TeX')
    need(TITLE in tex, 'TeX/CFF title mismatch')
    old_check = 'check: a249110\n\tpython3 -B ../validation/check.py\n\tpython3 -B ../validation/wide.py\n'
    new_check = 'check: a249110\n\tpython3 -B ../check/verify.py native\n'
    return tex, old_check, new_check

def indexed_files(index):
    result = []
    destinations = set()
    for arc in index['archives']:
        safe(arc['path'])
        need(arc['path'] in ('proof/run.tgz','proof/dev.tgz','proof/logs.tgz'), 'archive path')
        raw = (ROOT/arc['path']).read_bytes()
        need(len(raw) == arc['bytes'] and digest(raw) == arc['sha256'], 'archive identity')
        rows = arc['members']
        need(len({r['member'] for r in rows}) == len(rows), 'duplicate archive index')
        with tarfile.open(ROOT/arc['path'], 'r:gz') as tar:
            members = tar.getmembers()
            need([m.name for m in members] == [r['member'] for r in rows], 'archive inventory/order')
            for member, row in zip(members, rows):
                safe(row['member']); safe(row['restore'])
                need(len(PurePosixPath(row['member']).parts) == 1 and member.isfile(), 'special archive entry')
                if PurePosixPath(row['restore']).suffix in ('.c','.py','.tex'):
                    need(row['member'] == PurePosixPath(row['restore']).name,
                         'archived programs retain their meaningful canonical basenames')
                need(row['restore'] not in destinations, 'duplicate restore destination')
                need(member.mode == row['mode'] and row['mode'] in (0o600,0o644,0o664,0o755,0o775), 'archive mode')
                need(member.size == row['bytes'], 'archive size')
                data = tar.extractfile(member).read()
                need(digest(data) == row['sha256'], 'archive member hash')
                destinations.add(row['restore']); result.append((row['restore'],data,row['mode']))
        need(sum(r['bytes'] for r in rows) == arc['expanded_bytes'], 'expanded size')
    need(len(index['archives']) == 3, 'archive cardinality')
    for row in index['shared']:
        safe(row['path']); safe(row['restore'])
        raw = (ROOT/row['path']).read_bytes()
        need(row['restore'] not in destinations and len(raw) == row['bytes']
             and digest(raw) == row['sha256'], 'shared identity/destination')
        need(row['mode'] == 0o644, 'shared mode')
        destinations.add(row['restore']); result.append((row['restore'],raw,row['mode']))
    return result

def restore(destination, files):
    destination = destination.absolute()
    need(not destination.exists() and not destination.is_symlink(), 'restore destination already exists')
    need(not destination.resolve().is_relative_to(ROOT), 'restore must be outside the publication payload')
    need(destination.parent.is_dir(), 'restore parent missing')
    destination.mkdir(mode=0o700)
    for name, raw, mode in files:
        p = destination.joinpath(*safe(name).parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open('xb') as f:
            f.write(raw)
        p.chmod(mode)

def arithmetic_and_records(work, tex):
    record = load(ROOT/'check/records.py','a249110_records')
    afile = load(ROOT/'check/afile.py','a249110_afile')
    report = afile.audit(ROOT/'data/b249110.txt', ROOT/'data/a249110.txt')
    need(report['rows'] == 9, 'nine canonical rows')
    runs = []
    for name, expected in [('first',('DONE',2,1072281223,1)),
                           ('5E10',('INCOMPLETE',29,20246541959,3)),
                           ('22E9',('DONE',3,22000000000,0))]:
        r = record.audit(work/'runs'/name, work)
        need(tuple(r[k] for k in ('state','segments_sealed','frontier','sealed_hits')) == expected,
             'run status/frontier: '+name)
        runs.append(r)
    rawcfg = (work/'runs/first/run.cfg').read_bytes()
    baseline = rawcfg.split(b'baseline\n',1)[1].rsplit(b'endbase\n',1)[0]
    values = [int(r.split()[1]) for r in baseline.splitlines() if r]
    for name in ('first','5E10','22E9'):
        hits = (work/'runs'/name/'hits.tsv').read_text().splitlines()[2:]
        values.extend(int(r.split('\t')[0]) for r in hits)
    generated_b = ''.join(f'{i} {n}\n' for i,n in enumerate(values,1)).encode()+b'\n'
    need(generated_b == (ROOT/'data/b249110.txt').read_bytes(), 'b-file provenance regeneration')
    a_raw = (ROOT/'data/a249110.txt').read_bytes()
    header = b''.join(line for line in a_raw.splitlines(keepends=True) if line.startswith(b'#'))
    generated_a = bytearray(header)
    for i,n in enumerate(values,1):
        chain = [n]
        for _ in range(8):
            chain.append(record.derivative(chain[-1]))
        q = sum(x*x for x in chain); rt = math.isqrt(q)
        need(rt*rt == q, 'regenerated positive square')
        generated_a.extend((' '.join(map(str,[i,*chain,rt]))+'\n').encode())
    generated_a.extend(b'\n')
    need(bytes(generated_a) == a_raw, 'a-file regenerated numeric rows/framing')
    analysis = json.loads(command([sys.executable,'-B','-O',work/'paper/analyze.py']))
    need(analysis['form_count'] == 5 and analysis['classified_inputs'] == 21999176457
         and analysis['totals']['blocks'] == 83921, 'finite analysis/coverage')
    for form,i in {'F_0':1,'F_1':7,'E_4':4,'E_6':6,'E_9':9}.items():
        m = re.search(re.escape(form)+r'=\{\}&\((.*?)\)',tex,re.S)
        need(m is not None and [int(v) for v in re.findall(r'\d+',m[1])] == analysis['rows'][i-1]['primitive'],
             'TeX primitive-form drift: '+form)
    cal = work/'outputs/rev5/calraw'
    arms = []
    for d in sorted(p for p in cal.iterdir() if p.is_dir()):
        r = record.audit(d,work)
        need(r['state'] == 'DONE', 'calibration record incomplete')
        arms.append(r)
    need(len(arms) == 8, 'eight original calibration arms')
    fixture_dir = work/'fresh'
    command([sys.executable,'-B','-O',work/'validation/fixtures.py','--write',fixture_dir])
    need((fixture_dir/'cases.json').read_bytes() == (work/'outputs/precode/cases.json').read_bytes(),
         'finite fixture byte regeneration')
    shutil.rmtree(fixture_dir)
    return {'documentary':report,'runs':runs,'forms':analysis['form_count'],
            'classified_inputs':analysis['classified_inputs'],'committed_blocks':83921,
            'calibration_arms_audited':len(arms),'fixture_regeneration':'byte-identical',
            'independent_negative_enumeration':False}

def native(work):
    need(sys.platform.startswith('linux'), 'native mode requires Linux /proc and flock')
    old = work/'src/a249110'
    for name, rc in [('first',0),('5E10',2),('22E9',0)]:
        command([old,'verify',work/'runs'/name], expected=rc)
    with tempfile.TemporaryDirectory(prefix='a249110-build-') as td:
        p = Path(td)
        (p/'src').mkdir(); (p/'data').mkdir()
        for name in ('a249110.c','Makefile'):
            shutil.copyfile(ROOT/'src'/name,p/'src'/name)
        shutil.copyfile(ROOT/'data/b249110.txt',p/'data/b249110.txt')
        command(['make','-C',p/'src','all'])
        exe = p/'src/a249110'
        record = load(ROOT/'check/records.py','a249110_native_expected')
        windows = [(2,256),(398747,398747),(1072281223,1072281223),
                   (10361580899,10361580899),(34359738368,34359738368)]
        for i,(lo,hi) in enumerate(windows):
            d = p/f't{i}'
            command([exe,'init',d,lo,hi,1,2])
            command([exe,'next',d]); command([exe,'verify',d])
            expected = []
            for n in range(lo,hi+1):
                chain = [n]
                for _ in range(8):chain.append(record.derivative(chain[-1]))
                q = sum(x*x for x in chain); r = math.isqrt(q)
                if r*r == q:expected.append([*chain,r])
            got = [list(map(int,line.split('\t'))) for line in (d/'hits.tsv').read_text().splitlines()[2:]]
            need(got == expected, 'fresh public binary versus trial division')
        # The routing-adapted fresh public build must not claim the historical run.
        command([exe,'verify',work/'runs/22E9'],expected=1)
        return {'fresh_public_build':True,'temporary_distinct_inputs':259,
                'historical_binary_replays':[0,2,0],
                'public_binary_not_historical_run_identity':True,
                'fresh_binary_sha256':digest(exe.read_bytes())}

def development(work):
    # Rebuild the original unchanged recipe in scratch, never replace the saved
    # historical executable in the archive or claim its hash for a new build.
    with tempfile.TemporaryDirectory(prefix='a249110-dev-') as td:
        p = Path(td)/'tree'; shutil.copytree(work,p)
        command(['make','-B','-C',p/'src','all'])
        command([sys.executable,'-B','-O',p/'validation/check.py','--quick'],timeout=120)
        command([sys.executable,'-B','-O',p/'validation/wide.py'],timeout=120)
    return {'quick_original_suite':'PASS','wide_original_suite':'PASS',
            'sanitizers_benchmarks_and_signal_matrix_rerun':False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',nargs='?',choices=('check','native','dev','restore'),default='check')
    parser.add_argument('destination',nargs='?',type=Path)
    args = parser.parse_args()
    need((args.action == 'restore') == (args.destination is not None), 'restore requires exactly one destination')
    before = integrity()
    index = plain_json((ROOT/'proof/map.json').read_bytes())
    tex, old_check, new_check = metadata(index)
    files = indexed_files(index)
    if args.action == 'restore':
        restore(args.destination,files)
        print(json.dumps({'status':'RESTORED','destination':str(args.destination),'files':len(files)}))
        return
    with tempfile.TemporaryDirectory(prefix='a249110-records-') as td:
        work = Path(td)/'tree'; restore(work,files)
        for name,h in index['historical_identity'].items():
            need(digest((work/name).read_bytes()) == h, 'historical producer binding')
        old = (work/'src/Makefile').read_text(); new = (ROOT/'src/Makefile').read_text()
        need(old.count(old_check) == 1 and old.replace(old_check,new_check) == new,
             'only check routing may differ in public Makefile')
        need(digest(new.encode()) == index['public_makefile_sha256'], 'public Makefile identity')
        diff = ''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),
                      fromfile='historical/src/Makefile',tofile='public/src/Makefile'))
        need(diff == (ROOT/'proof/name.diff').read_text(), 'Makefile exact diff')
        result = {'status':'PASS','scope':'local retained-data checks; not publication certification',
                  'files_checked':len(before),'archive_members':sum(len(a['members']) for a in index['archives']),
                  **arithmetic_and_records(work,tex)}
        if args.action in ('native','dev'):result['native'] = native(work)
        if args.action == 'dev':result['development'] = development(work)
    need(before == integrity(), 'payload changed during checking')
    result['commands'] = CALLS
    print(json.dumps(result,indent=2))

if __name__ == '__main__':
    sys.dont_write_bytecode = True
    try:
        main()
    except (ValueError,OSError,KeyError,TypeError,UnicodeError,tarfile.TarError,
            subprocess.SubprocessError,ImportError) as error:
        print('REFUSE:',error,file=sys.stderr)
        raise SystemExit(1)
