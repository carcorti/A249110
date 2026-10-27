#!/usr/bin/env python3
"""Independent read-only A249110 record/witness checker, Python 3.11+ stdlib.

No C import or producer invocation. Exact trial division and isqrt check saved
positives. Coverage is audited from records, not independently re-enumerated.
The seven/twelve-base premises and producer correctness remain completeness dependencies.
"""
from pathlib import Path
import argparse,hashlib,json,math,re
CAP=50000000000;B=262144;H=1000000
LIMITS=[50000000000,797790175232,14345190768640,294669116243968,6755399441055744,174514485560606720,4643211215818981376,142962266571249025024,4574792530279968800768,4577028129111728646739]
def need(ok,msg):
    if not ok:raise ValueError(msg)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def num(s):
    need(re.fullmatch(r'0|[1-9][0-9]*',s) is not None,'decimal grammar');return int(s)
def hx(s):
    need(re.fullmatch('[0-9a-f]{64}',s) is not None,'hash grammar');return s
def lines(raw):
    need(raw.endswith(b'\n') and b'\r' not in raw and b'\0' not in raw,'framing')
    rr=raw.decode('ascii').splitlines();need(all(len(x)<255 for x in rr),'record width');return rr
def derivative(n):
    if n<2:return 0
    rem=n;total=0;p=2
    while p<=rem//p:
        e=0
        while rem%p==0:rem//=p;e+=1
        total+=e*(n//p);p=3 if p==2 else p+2
    if rem>1:total+=n//rem
    return total
def positive(row):
    need(len(row)==10 and all(0<=v<=m for v,m in zip(row,LIMITS)) and row[0]>=2 and row[1]>0 and row[-1]>0,'positive domain')
    for j in range(8):need(derivative(row[j])==row[j+1],'positive derivative mismatch')
    q=sum(x*x for x in row[:9]);need(math.isqrt(q)==row[9] and row[9]**2==q,'positive square mismatch')
def fields(rr,keys):
    need(len(rr)==len(keys),'field count');out={}
    for r,k in zip(rr,keys):
        a=r.split('\t');need(len(a)==2 and a[0]==k,'field order');out[k]=a[1]
    return out
def audit(d,source_root=None):
    for p in d.iterdir():need(p.is_file() and not p.is_symlink(),'special/symlink artifact')
    cfg=(d/'run.cfg').read_bytes();rr=lines(cfg);need(rr[0]=='A249110-CFG','config magic')
    fixed=['low','high','block','segments','workers','source_sha','makefile_sha','binary_sha','gmp','openssl','openmp']+[f'bound{i}' for i in range(9)]+['rootmax','baseline_sha']
    c=fields(rr[1:1+len(fixed)],fixed);at=1+len(fixed)
    need(rr[at]=='baseline' and rr[-1]=='endbase' and rr[-2]=='','baseline delimiters')
    base='\n'.join(rr[at+1:-1])+'\n';need(sha(base.encode())==hx(c['baseline_sha']),'baseline hash')
    bv=[]
    for j,r in enumerate(rr[at+1:-2],1):
        cols=r.split(' ');need(len(cols)==2 and num(cols[0])==j,'baseline indices')
        v=num(cols[1]);need(2<=v<=CAP and (not bv or v>bv[-1]),'baseline values');bv.append(v)
    need(5<=len(bv)<=H and bv[:5]==[4,27,3125,398747,823543],'admitted prefix')
    for v in bv:
        xs=[v]
        for _ in range(8):xs.append(derivative(xs[-1]))
        q=sum(z*z for z in xs);need(math.isqrt(q)**2==q,'baseline member')
    low,high,s,w=map(num,[c['low'],c['high'],c['segments'],c['workers']]);k=(high-low)//B+1
    need(2<=low<=high<=CAP and num(c['block'])==B and 1<=s<=min(256,k) and 1<=w<=16,'config domain')
    need([num(c[f'bound{i}']) for i in range(9)]==LIMITS[:9] and num(c['rootmax'])==LIMITS[9],'bound ledger')
    for key in ['source_sha','makefile_sha','binary_sha']:hx(c[key])
    if source_root:
        for file,key in [('a249110.c','source_sha'),('Makefile','makefile_sha'),('a249110','binary_sha')]:need(sha((source_root/'src'/file).read_bytes())==c[key],'producer identity')
    cfgsha=sha(cfg);sealed=0;frontier=low-1;allhits=[];manifest=[];open_seen=False;allcount=0;allowed={'run.cfg','man.tsv','hits.tsv','run.tmp','man.tmp','hits.tmp'}
    hit_boundaries={0}
    for j in range(s):
        lo=low+(j*k//s)*B;hi=min(high,low+((j+1)*k//s)*B-1)
        name=f's{j:03}';allowed|={name+'.tsv',name+'.sha',name+'.tmp'}
        raw=(d/(name+'.tsv')).read_bytes();sr=lines(raw)
        need(sr[0]=='A249110-STATE' and sr[-1].startswith('state_sha\t'),'state magic/footer')
        pre=raw[:-(len(sr[-1])+1)];need(sha(pre)==hx(sr[-1].split('\t')[1]),'state digest')
        keys=['cfg_sha','id','low','high','frontier','blocks','elapsed_ns','fallbacks','hits'];st=fields(sr[1:10],keys)
        f=num(st['frontier']);n=num(st['hits']);units=(f-lo+1+B-1)//B
        need(st['cfg_sha']==cfgsha and num(st['id'])==j and num(st['low'])==lo and num(st['high'])==hi and lo-1<=f<=hi and (f==hi or (f-lo+1)%B==0),'state identity/frontier')
        need(num(st['blocks'])==units and n<=min(H,f-lo+1) and num(st['fallbacks'])<=f-lo+1,'state counters')
        need(num(st['elapsed_ns'])<2**64 and num(st['fallbacks'])<2**64,'counter width')
        need(f!=lo-1 or (num(st['elapsed_ns'])==num(st['fallbacks'])==0),'initial counters')
        need(len(sr)==n+11,'state row count');hh=[]
        for line in sr[10:-1]:
            need(line.startswith('hit\t'),'hit prefix');row=list(map(num,line[4:].split('\t')));positive(row)
            need(lo<=row[0]<=f and (not hh or row[0]>hh[-1][0]),'hit ordering');hh.append(row)
        allcount+=n;need(allcount<=H,'global hit guard')
        seal=d/(name+'.sha')
        if open_seen:need(not seal.exists() and f==lo-1 and n==0,'future authority')
        else:
            need(lo==frontier+1,'coverage adjacency');frontier=f
            expected=[v for v in bv if lo<=v<=f];actual=[r[0] for r in hh if r[0]<=bv[-1]];need(actual==expected,'baseline correspondence')
            if seal.exists():
                need(f==hi and seal.read_bytes()==(sha(raw)+'\n').encode(),'seal identity');sealed+=1
                manifest.append(f'{j}\t{lo}\t{hi}\t{units}\t{sha(raw)}\t{st["elapsed_ns"]}\t{st["fallbacks"]}\t{n}')
                allhits+=hh;hit_boundaries.add(len(allhits))
            else:open_seen=True
    for p in d.iterdir():need(p.name in allowed,'foreign artifact')
    derived=True
    for name,magic,header,expected,boundaries in [
        ('man.tsv','A249110-MAN','id\tlow\thigh\tblocks\tstate_sha\telapsed_ns\tfallbacks\thits',manifest,set(range(sealed+1))),
        ('hits.tsv','A249110-HITS','n\tx1\tx2\tx3\tx4\tx5\tx6\tx7\tx8\tR',['\t'.join(map(str,r)) for r in allhits],hit_boundaries)]:
        p=d/name
        if not p.exists():derived=False;continue
        r=lines(p.read_bytes());need(r[:2]==[magic+'\tcfg_sha='+cfgsha,header],'aggregate identity')
        n=len(r)-2;need(n in boundaries and r[2:]==expected[:n],'aggregate prefix');derived&=n==len(expected)
    return {'state':'DONE' if sealed==s and derived else 'INCOMPLETE','segments_sealed':sealed,'segments':s,'frontier':frontier,'sealed_hits':len(allhits),'saved_hits':allcount,'independent_negative_enumeration':False,'positive_backend':'complete trial division/Python isqrt','cfg_sha256':cfgsha}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('run',type=Path);ap.add_argument('--source-root',type=Path);a=ap.parse_args()
    try:r=audit(a.run,a.source_root)
    except (ValueError,OSError,UnicodeError,IndexError) as e:print('REFUSE:',e);raise SystemExit(1)
    print(json.dumps(r,indent=2));raise SystemExit(0 if r['state']=='DONE' else 2)
if __name__=='__main__':main()
