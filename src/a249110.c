/*
 * A249110: exact Q8 interval classification, n >= 2.
 * Copyright (c) 2026 Carlo Corti.
 * D(0)=D(1)=0; D(n)=sum e*(n/p). Nine squares, eight compositions.
 * Null tails allowed; no primitivity/family filter. No ranks are assigned.
 * Linux LP64; C17 with unsigned __int128, OpenMP, GMP, OpenSSL libcrypto.
 * Word primality uses the external seven-base finite-domain premise below
 * 2^64 (Sinclair set catalogued at miller-rabin.appspot.com); not a new proof.
 * Wider final operands use the first twelve prime bases below psi_12 from
 * Sorenson--Webster, arXiv:1509.00864, Theorem 1.1; not a new proof.
 * Rho accelerates exact factoring; trial division is the terminating fallback.
 * First-derivative sieve and low-level exact-factor helpers adapted from the
 * read-only A249107 source. Predicate, bounds and persistence are specific here.
 * Only completed blocks commit; interrupted work is INCOMPLETE (exit 2).
 * Build with the neighboring Makefile; CLI has init/next/status/verify only.
 */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <openssl/crypto.h>
#include <time.h>
#include <unistd.h>
#include <gmp.h>
#ifdef _OPENMP
#include <omp.h>
#endif

__extension__ typedef unsigned __int128 u128;
/* Conservative monotone 2-adic/odd-part envelope (capacity proof in cap.md):
   for a=0..floor(log2 U), M=largest odd <=floor(U/2^a), k=floor(log3 M),
   G(U)=max_a [a*2^(a-1)*M + 2^a*floor(M*k/3)], first summand zero at a=0.
   D(2^a*m)=a*2^(a-1)*m+2^a*D(m), D(odd m)<=floor(m*floor(log3 m)/3).
   Bounds are not observed maxima or execution authority. */
#define CAP UINT64_C(50000000000)
#define BLOCK UINT64_C(262144)
#define MAX_SEGMENTS UINT64_C(256)
#define MAX_THREADS 16
#define HIT_GUARD UINT64_C(1000000)
#define BASE_BYTES UINT64_C(22000000)
#define MAX_D7 (((u128)UINT64_C(7)<<64)|UINT64_C(13835058055282163712))
#define MAX_D8 ((u128)UINT64_C(248)<<64)
#define MAX_ROOT (((u128)UINT64_C(248)<<64)|UINT64_C(2235598831759845971))
#define WIDE_PRIME_LIMIT (((u128)UINT64_C(17274)<<64)|UINT64_C(16800704772356552677))
#define HIT_ROW_MAX 180
#define STATE_HIT_MAX (HIT_ROW_MAX+4)
#ifndef A249110_SOURCE_SHA
#error "build with the identity-binding Makefile"
#endif
#ifndef A249110_MAKE_SHA
#error "build with the identity-binding Makefile"
#endif
static const uint64_t bounds[7]={CAP,UINT64_C(797790175232),
 UINT64_C(14345190768640),UINT64_C(294669116243968),
 UINT64_C(6755399441055744),UINT64_C(174514485560606720),
 UINT64_C(4643211215818981376)};
#define MAX_PATH 4096
#define HASH_LEN 64

_Static_assert(SIZE_MAX == UINT64_MAX && sizeof(off_t) >= 8, "LP64 size/file domain required");
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal stop flag must be lock-free");
static _Atomic int stopped = 0;
static void on_signal(int signum) {
    (void)signum;
    atomic_store_explicit(&stopped, 1, memory_order_relaxed);
}
static bool stop_requested(void) {
    return atomic_load_explicit(&stopped, memory_order_relaxed) != 0;
}

static _Noreturn void die(const char *msg) {
    if(stop_requested()) { fprintf(stderr,"INCOMPLETE: signal during audit/work: %s\n",msg); exit(2); }
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(1);
}
static _Noreturn void sysdie(const char *msg) {
    int saved = errno;
    if (saved == EINTR && stop_requested()) exit(2);
    fprintf(stderr, "ERROR: %s: %s\n", msg, strerror(saved));
    exit(1);
}
static bool dec64(const char *s, uint64_t *out) {
    if (!s || !*s || (s[0]=='0' && s[1])) return false;
    uint64_t v = 0;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9') return false;
        unsigned d = (unsigned)(*s - '0');
        if (v > (UINT64_MAX - d) / 10) return false;
        v = v * 10 + d;
    }
    *out = v;
    return true;
}
static bool dec128(const char *s, u128 *out) {
    if (!s || !*s || (s[0]=='0' && s[1])) return false;
    u128 v = 0, top = ~(u128)0;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9') return false;
        unsigned d = (unsigned)(*s - '0');
        if (v > (top - d) / 10) return false;
        v = v * 10 + d;
    }
    *out = v;
    return true;
}
static void fmt128(u128 v, char out[40]) {
    char tmp[40];
    size_t k = 0;
    do { tmp[k++] = (char)('0' + v % 10); v /= 10; } while (v);
    for (size_t j = 0; j < k; ++j) out[j] = tmp[k - 1 - j];
    out[k] = 0;
}
static uint64_t isqrt64(uint64_t x) {
    uint64_t lo = 0, hi = UINT64_C(4294967295);
    while (lo < hi) {
        uint64_t mid = lo + (hi - lo + 1) / 2;
        if (mid <= x / mid) lo = mid; else hi = mid - 1;
    }
    return lo;
}
static uint64_t ns_now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) sysdie("clock_gettime");
    if(t.tv_sec<0 || t.tv_nsec<0 || t.tv_nsec>=1000000000L)
        die("monotonic clock domain");
    u128 value=(u128)(uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
    if(value>UINT64_MAX) die("monotonic clock width");
    return (uint64_t)value;
}
/* Main sets this immutable context before the OpenMP fork and changes it
   only after the implicit join. The deadline is the sole shared mutable field. */
static bool live_enabled=false;
static uint64_t live_target,live_segment,live_segments,live_frontier,live_begin,live_units,live_fallbacks;
static _Atomic uint64_t next_note=0;
static _Thread_local uint64_t active_input=0;
static void heartbeat(u128 operand) {
    if(!live_enabled) return;
    uint64_t now=ns_now();
    uint64_t due=atomic_load_explicit(&next_note,memory_order_relaxed);
    if(now<due) return;
    if(now>UINT64_MAX-UINT64_C(10000000000)) die("heartbeat clock overflow");
    if(!atomic_compare_exchange_strong_explicit(&next_note,&due,
           now+UINT64_C(10000000000),memory_order_relaxed,memory_order_relaxed)) return;
    if(now<live_begin) die("monotonic clock wrapped");
    char operand_text[40]; fmt128(operand,operand_text);
    fprintf(stderr,"HEARTBEAT A249110 target=%" PRIu64 " segment=%" PRIu64
            "/%" PRIu64 " checkpoint_frontier=%" PRIu64 " blocks=%" PRIu64 " saved_fallback_inputs=%" PRIu64 " active_input=%" PRIu64
            " factor_operand=%s call_elapsed_s=%.0f uncommitted_block\n",
            live_target,live_segment,live_segments,live_frontier,live_units,live_fallbacks,active_input,operand_text,
            (double)(now-live_begin)/1e9);
}
static void path2(char out[MAX_PATH], const char *dir, const char *base) {
    int n = snprintf(out, MAX_PATH, "%s/%s", dir, base);
    if (n < 0 || n >= MAX_PATH) die("path too long");
}
static void sync_dir(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) sysdie("open directory");
    if (fsync(fd)) sysdie("fsync directory");
    if (close(fd)) sysdie("close directory");
}
static bool exists(const char *path) {
    struct stat st;
    if(lstat(path,&st)) { if(errno==ENOENT) return false; sysdie("lstat"); }
    if(!S_ISREG(st.st_mode)) die("nonregular/symlink artifact");
    return true;
}
static FILE *input(const char *path) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0) sysdie("open input");
    struct stat st;
    if(fstat(fd,&st)) sysdie("fstat input");
    if(!S_ISREG(st.st_mode)) die("nonregular input");
    FILE *f=fdopen(fd,"r");
    if(!f) sysdie("fdopen input");
    return f;
}
static void hash_file(const char *path, char hex[HASH_LEN + 1]) {
    unsigned char digest[EVP_MAX_MD_SIZE], buf[16384];
    unsigned int length = 0;
    FILE *f = input(path);
    if (!f) sysdie("open hash input");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) die("EVP allocation");
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) die("EVP init");
    for (;;) {
        size_t n = fread(buf, 1, sizeof buf, f);
        if (n && EVP_DigestUpdate(ctx, buf, n) != 1) die("EVP update");
        if (n < sizeof buf) {
            if (ferror(f)) sysdie("read hash input");
            break;
        }
    }
    if (EVP_DigestFinal_ex(ctx, digest, &length) != 1 || length != 32)
        die("EVP final");
    EVP_MD_CTX_free(ctx);
    if (fclose(f)) sysdie("close hash input");
    static const char hexd[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; ++i) {
        hex[2*i] = hexd[digest[i] >> 4];
        hex[2*i+1] = hexd[digest[i] & 15];
    }
    hex[64] = 0;
}
/* Hash an exact serialized prefix, excluding the segment's own footer. */
static void hash_stream_prefix(FILE *f, off_t length,
                               char hex[HASH_LEN + 1]) {
    if (length < 0) die("negative hash prefix");
    unsigned char digest[EVP_MAX_MD_SIZE], buf[16384];
    unsigned int digest_length = 0;
    if (fseeko(f,0,SEEK_SET)) sysdie("seek hash prefix");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) die("EVP allocation");
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) die("EVP init");
    uint64_t remaining = (uint64_t)length;
    while (remaining) {
        size_t want = remaining < sizeof buf ? (size_t)remaining : sizeof buf;
        size_t n = fread(buf, 1, want, f);
        if (n != want) {
            if (ferror(f)) sysdie("read hash prefix");
            die("short hash prefix");
        }
        if (EVP_DigestUpdate(ctx, buf, n) != 1) die("EVP update");
        remaining -= n;
    }
    if (EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
        digest_length != 32) die("EVP final");
    EVP_MD_CTX_free(ctx);
    static const char hexd[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; ++i) {
        hex[2*i] = hexd[digest[i] >> 4];
        hex[2*i+1] = hexd[digest[i] & 15];
    }
    hex[64] = 0;
}
static void hash_file_prefix(const char *path, off_t length,
                             char hex[HASH_LEN + 1]) {
    FILE *f = input(path);
    if (!f) sysdie("open hash prefix");
    hash_stream_prefix(f,length,hex);
    if (fclose(f)) sysdie("close hash prefix");
}
static bool valid_hash(const char *s) {
    if (strlen(s) != HASH_LEN) return false;
    for (size_t i = 0; i < HASH_LEN; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}


/* Fixed grammar: every valid record, including the widest hit, is <256 bytes.
   Reject embedded NUL/CR and oversized/truncated records before allocation grows. */
static bool read_line(FILE *f, char **buf, size_t *cap) {
    if (*cap < 256) {
        char *p=realloc(*buf,256);
        if(!p) die("record allocation");
        *buf=p; *cap=256;
    }
    size_t n=0;
    for(;;) {
        int ch=fgetc(f);
        if(ch==EOF) {
            if(ferror(f)) sysdie("read record");
            if(n) die("truncated record");
            return false;
        }
        if(ch==0 || ch=='\r') die("NUL/CR in record");
        if(ch=='\n') { (*buf)[n]=0; return true; }
        if(n==254) die("oversized record");
        (*buf)[n++]=(char)ch;
    }
}
static void expect_eof(FILE *f, const char *what) {
    int ch=fgetc(f);
    if(ferror(f)) sysdie("read trailing record");
    if(ch!=EOF) die(what);
}
static void expect_key(FILE *f, char **line, size_t *cap, const char *key,
                       char **value) {
    if (!read_line(f,line,cap)) die("missing record field");
    size_t k = strlen(key);
    if (strncmp(*line,key,k) || (*line)[k] != '\t')
        die("record field mismatch");
    *value = *line+k+1;
}
static uint64_t field64(FILE *f, char **line, size_t *cap, const char *key) {
    char *v; uint64_t x;
    expect_key(f,line,cap,key,&v);
    if (!dec64(v,&x)) die("invalid integer field");
    return x;
}
static void fieldhash(FILE *f, char **line, size_t *cap, const char *key,
                      char hash[65]) {
    char *v;
    expect_key(f,line,cap,key,&v);
    if (!valid_hash(v)) die("invalid hash field");
    memcpy(hash,v,65);
}

static uint64_t gcd64(uint64_t a,uint64_t b) {
    while(b) { uint64_t t=a%b; a=b; b=t; }
    return a;
}
static uint64_t mulmod(uint64_t a,uint64_t b,uint64_t m) {
    return (uint64_t)(((u128)a*b)%m);
}
static uint64_t powmod(uint64_t a,uint64_t e,uint64_t m) {
    uint64_t r=1;
    while(e) {
        if(e&1) r=mulmod(r,a,m);
        e>>=1;
        if(e) a=mulmod(a,a,m);
    }
    return r;
}
/* Deterministic for every uint64_t, not merely for a decimal subrange. */
static bool prime64(uint64_t n) {
    static const uint64_t small[]={2,3,5,7,11,13,17,19,23,29,31,37};
    if(n<2) return false;
    for(size_t i=0;i<sizeof small/sizeof small[0];++i) {
        if(n==small[i]) return true;
        if(n%small[i]==0) return false;
    }
    uint64_t d=n-1; unsigned s=0;
    while(!(d&1)) { d>>=1; ++s; }
    static const uint64_t bases[]={
        2,325,9375,28178,450775,9780504,1795265022
    };
    for(size_t i=0;i<sizeof bases/sizeof bases[0];++i) {
        uint64_t a=bases[i]%n;
        if(!a) continue;
        uint64_t x=powmod(a,d,n);
        if(x==1||x==n-1) continue;
        bool pass=false;
        for(unsigned j=1;j<s;++j) {
            x=mulmod(x,x,n);
            if(x==n-1) { pass=true; break; }
        }
        if(!pass) return false;
    }
    return true;
}
static uint64_t rho_step(uint64_t x,uint64_t c,uint64_t n) {
    return (uint64_t)(((u128)x*x+c)%n);
}
static uint64_t split64(uint64_t n,bool *fallback) {
    static const uint32_t small[]={2,3,5,7,11,13,17,19,23,29,31,37,
        41,43,47,53,59,61,67,71,73,79,83,89,97};
    for(size_t i=0;i<sizeof small/sizeof small[0];++i)
        if(n%small[i]==0) return small[i];
    /* Fixed seeds and effort make the fast path reproducible. */
#ifndef A249110_FORCE_FALLBACK
    for(uint64_t c=1;c<=32;++c) {
        uint64_t x=(2+c)%n,y=x,d=1;
        for(uint64_t k=0;k<100000 && d==1;++k) {
            if(stop_requested()) return 0;
            if((k & 4095)==0) heartbeat(n);
            x=rho_step(x,c,n);
            y=rho_step(rho_step(y,c,n),c,n);
            uint64_t delta=x>y?x-y:y-x;
            d=gcd64(delta,n);
        }
        if(d>1&&d<n) return d;
    }
#endif
    /* Exact terminating fallback. It can be slow on an adversarial
       semiprime; interruption is an incomplete block, never a miss. */
    *fallback=true;
    for(uint64_t p=101;p<=n/p;p+=2) {
        if(stop_requested()) return 0;
        if((p & UINT64_C(131071))==101) heartbeat(n);
        if(n%p==0) return p;
    }
    return 0;
}
static bool factor_rec(uint64_t n,uint64_t fac[64],unsigned *nf,
                       bool *fallback) {
    if(n==1) return true;
    if(prime64(n)) {
        if(*nf>=64) return false;
        fac[(*nf)++]=n;
        return true;
    }
    uint64_t d=split64(n,fallback);
    if(d<=1||d>=n||n%d) return false;
    return factor_rec(d,fac,nf,fallback) &&
           factor_rec(n/d,fac,nf,fallback);
}
static int cmp64(const void *a,const void *b) {
    uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;
    return (x>y)-(x<y);
}
static bool derivative64(uint64_t n,u128 *out,bool *fallback) {
    if(n<2) { *out=0; return true; }
    uint64_t fac[64], rem=n; unsigned nf=0;
    static const uint32_t small[]={2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97};
    for(size_t k=0;k<sizeof small/sizeof small[0];++k) {
        uint64_t p=small[k];
        while(rem%p==0) {
            if(nf>=64) return false;
            fac[nf++]=p; rem/=p;
        }
        if(rem==1) break;
    }
    if(!factor_rec(rem,fac,&nf,fallback)) return false;
    qsort(fac,nf,sizeof fac[0],cmp64);
    u128 prod=1,sum=0;
    for(unsigned i=0;i<nf;) {
        uint64_t p=fac[i]; unsigned e=0;
        if(!prime64(p)) return false;
        while(i<nf&&fac[i]==p) {
            prod*=p;
            if(prod>n) return false;
            ++e; ++i;
        }
        sum+=(u128)e*(n/p);
    }
    if(prod!=n) return false;
    *out=sum;
    return true;
}
static void mpz_set128(mpz_t z,u128 x) {
    uint64_t limbs[2]={(uint64_t)(x>>64),(uint64_t)x};
    mpz_import(z,2,1,sizeof(uint64_t),0,0,limbs);
}
static bool mpz_get128_checked(const mpz_t z,u128 *x) {
    if(mpz_sgn(z)<0||mpz_sizeinbase(z,2)>128) return false;
    uint64_t limbs[2]={0,0}; size_t count=0;
    mpz_export(limbs,&count,1,sizeof(uint64_t),0,0,z);
    if(count>2) return false;
    *x=(count==2?((u128)limbs[0]<<64)|limbs[1]:
         count==1?limbs[0]:0);
    return true;
}

/* GMP is used only for the final operand when it actually exceeds u64.
   Scratch belongs to one worker/caller; no process-global GMP state. */
typedef struct { mpz_t mod,x,y,tmp,delta,divisor,exp,base; } WideScratch;
static void wide_init(WideScratch *s) {
    mpz_inits(s->mod,s->x,s->y,s->tmp,s->delta,s->divisor,s->exp,s->base,NULL);
}
static void wide_clear(WideScratch *s) {
    mpz_clears(s->mod,s->x,s->y,s->tmp,s->delta,s->divisor,s->exp,s->base,NULL);
}
/* Exact under the named finite-domain premise, for n < WIDE_PRIME_LIMIT.
   Every production caller is additionally bounded by MAX_D7 < that limit. */
static bool prime_wide(u128 n,WideScratch *s) {
    if(n<=UINT64_MAX) return prime64((uint64_t)n);
    if(n>=WIDE_PRIME_LIMIT) return false;
    static const uint32_t bases[]={2,3,5,7,11,13,17,19,23,29,31,37};
    for(size_t j=0;j<sizeof bases/sizeof bases[0];++j)
        if(n%bases[j]==0) return false;
    u128 d=n-1; unsigned shift=0;
    while(!(d&1)) { d>>=1; ++shift; }
    mpz_set128(s->mod,n); mpz_set128(s->exp,d);
    for(size_t j=0;j<sizeof bases/sizeof bases[0];++j) {
        if(stop_requested()) return false;
        heartbeat(n);
        mpz_set_ui(s->base,bases[j]);
        mpz_powm(s->x,s->base,s->exp,s->mod);
        u128 x;
        if(!mpz_get128_checked(s->x,&x)) return false;
        if(x==1||x==n-1) continue;
        bool pass=false;
        for(unsigned k=1;k<shift;++k) {
            if(stop_requested()) return false;
            mpz_mul(s->x,s->x,s->x); mpz_mod(s->x,s->x,s->mod);
            if(!mpz_get128_checked(s->x,&x)) return false;
            if(x==n-1) { pass=true; break; }
        }
        if(!pass) return false;
    }
    return true;
}
static void rho_wide_step(mpz_t out,const mpz_t in,unsigned long c,WideScratch *s) {
    mpz_mul(s->tmp,in,in); mpz_add_ui(s->tmp,s->tmp,c);
    mpz_mod(out,s->tmp,s->mod);
}
static u128 split_wide(u128 n,bool *fallback,WideScratch *s) {
    static const uint32_t small[]={2,3,5,7,11,13,17,19,23,29,31,37,
        41,43,47,53,59,61,67,71,73,79,83,89,97};
    for(size_t j=0;j<sizeof small/sizeof small[0];++j)
        if(n%small[j]==0) return small[j];
#ifndef A249110_FORCE_FALLBACK
    mpz_set128(s->mod,n);
    for(unsigned long c=1;c<=32;++c) {
        mpz_set_ui(s->x,2+c); mpz_set(s->y,s->x); mpz_set_ui(s->divisor,1);
        for(uint64_t k=0;k<100000&&mpz_cmp_ui(s->divisor,1)==0;++k) {
            if(stop_requested()) return 0;
            if((k&4095)==0) heartbeat(n);
            rho_wide_step(s->x,s->x,c,s);
            rho_wide_step(s->y,s->y,c,s); rho_wide_step(s->y,s->y,c,s);
            mpz_sub(s->delta,s->x,s->y); mpz_abs(s->delta,s->delta);
            mpz_gcd(s->divisor,s->delta,s->mod);
        }
        u128 factor;
        if(mpz_get128_checked(s->divisor,&factor)&&factor>1&&factor<n) return factor;
    }
#endif
    *fallback=true;
    /* n <= MAX_D7 < 2^67, hence the last p and p+2 are below 2^34.
       Earlier small-prime tests cover every divisor less than 101. */
    for(uint64_t p=101;(u128)p<=n/p;p+=2) {
        if(stop_requested()) return 0;
        if((p&UINT64_C(131071))==101) heartbeat(n);
        if(n%p==0) return p;
    }
    return 0;
}
static bool factor_rec_wide(u128 n,u128 fac[67],unsigned *nf,
                            bool *fallback,WideScratch *s) {
    if(stop_requested()) return false;
    if(n==1) return true;
    if(n<=UINT64_MAX) {
        uint64_t word[64]; unsigned count=0;
        if(!factor_rec((uint64_t)n,word,&count,fallback)||count>67-*nf) return false;
        for(unsigned j=0;j<count;++j) fac[(*nf)++]=word[j];
        return true;
    }
    if(prime_wide(n,s)) {
        if(*nf>=67) return false;
        fac[(*nf)++]=n; return true;
    }
    u128 factor=split_wide(n,fallback,s);
    if(factor<=1||factor>=n||n%factor) return false;
    return factor_rec_wide(factor,fac,nf,fallback,s)&&
           factor_rec_wide(n/factor,fac,nf,fallback,s);
}
static int cmp128(const void *a,const void *b) {
    u128 x=*(const u128*)a,y=*(const u128*)b;
    return (x>y)-(x<y);
}
static bool derivative_wide(u128 n,u128 *out,bool *fallback,WideScratch *s) {
    if(n<=UINT64_MAX) return derivative64((uint64_t)n,out,fallback);
    if(n>MAX_D7) return false;
    u128 fac[67]; unsigned count=0;
    if(!factor_rec_wide(n,fac,&count,fallback,s)) return false;
    qsort(fac,count,sizeof fac[0],cmp128);
    u128 product=1,sum=0;
    for(unsigned j=0;j<count;) {
        u128 p=fac[j]; unsigned exponent=0;
        if(!prime_wide(p,s)) return false;
        while(j<count&&fac[j]==p) {
            if(product>n/p) return false;
            product*=p; ++exponent; ++j;
        }
        u128 add=(u128)exponent*(n/p);
        if(add>MAX_D8-sum) return false;
        sum+=add;
    }
    if(product!=n||stop_requested()) return false;
    *out=sum; return true;
}
static u128 chain_bound(unsigned j) {
    if(j<7) return bounds[j];
    if(j==7) return MAX_D7;
    if(j==8) return MAX_D8;
    die("chain bound index");
}
typedef struct { uint64_t x[7]; u128 x7,x8,root; } Hit;
_Static_assert(sizeof(Hit)<=128,"hit allocation domain");
static u128 hit_coordinate(const Hit *h,unsigned j) {
    return j<7?(u128)h->x[j]:j==7?h->x7:j==8?h->x8:h->root;
}
typedef struct { mpz_t sum,z,root; WideScratch wide; } Scratch;
static void scratch_init(Scratch *s) { mpz_inits(s->sum,s->z,s->root,NULL); wide_init(&s->wide); }
static void scratch_clear(Scratch *s) { wide_clear(&s->wide); mpz_clears(s->sum,s->z,s->root,NULL); }
/* HIT=1, MISS=0, INCOMPLETE=-1. The supplied d1 is an exact sieve value. */
static int predicate(uint64_t n,uint64_t d1,Hit *hit,bool *fallback,Scratch *s) {
    active_input=n;
    if(n<2||n>CAP||!d1||d1>bounds[1]) return -1;
    if(d1==1) return 0; /* Q8(prime)=n*n+1 lies between consecutive squares. */
    Hit h={.x={n,d1}};
    u128 value=0;
    for(unsigned j=2;j<=8;++j) {
        if(stop_requested()) return -1;
        u128 prev=hit_coordinate(&h,j-1);
        if(prev<2) value=0;
        else if(j>2 && prev==hit_coordinate(&h,j-2)) value=prev;
        else if(!derivative_wide(prev,&value,fallback,&s->wide)) return -1;
        if(j<7) {
            if(value>bounds[j]) return -1;
            h.x[j]=(uint64_t)value;
        } else if(j==7) { if(value>MAX_D7) return -1; h.x7=value; }
        else { if(value>MAX_D8) return -1; h.x8=value; }
    }
    mpz_set_ui(s->sum,0);
    for(unsigned j=0;j<9;++j) {
        mpz_set128(s->z,hit_coordinate(&h,j));
        mpz_mul(s->z,s->z,s->z); mpz_add(s->sum,s->sum,s->z);
    }
    if(!mpz_perfect_square_p(s->sum)) return 0;
    mpz_sqrt(s->root,s->sum);
    if(!mpz_get128_checked(s->root,&h.root)||!h.root||h.root>MAX_ROOT) return -1;
    mpz_mul(s->z,s->root,s->root);
    if(mpz_cmp(s->z,s->sum)) return -1;
    if(hit) *hit=h;
    return 1;
}
static bool equal_hit(const Hit *a,const Hit *b) {
    for(unsigned j=0;j<10;++j) if(hit_coordinate(a,j)!=hit_coordinate(b,j)) return false;
    return true;
}
static bool verified_hit(const Hit *h) {
    if(h->x[0]<2||h->x[0]>CAP) return false;
    bool fb=false; u128 d; Hit fresh; Scratch s; scratch_init(&s);
    bool yes=derivative64(h->x[0],&d,&fb)&&d<=bounds[1]&&
        predicate(h->x[0],(uint64_t)d,&fresh,&fb,&s)==1&&equal_hit(h,&fresh);
    scratch_clear(&s); return yes;
}
static size_t hit_text(const Hit *h,char out[256]) {
    size_t at=0;
    for(unsigned j=0;j<10;++j) {
        char val[40]; fmt128(hit_coordinate(h,j),val);
        int k=snprintf(out+at,256-at,"%s%c",val,j==9?'\n':'\t');
        if(k<0||(size_t)k>=256-at) die("hit format width");
        at+=(size_t)k;
    }
    return at;
}
static void parse_hit(char *line,Hit *h) {
    char *p=line;
    for(unsigned j=0;j<10;++j) {
        char *tab=strchr(p,'\t');
        if((j<9&&!tab)||(j==9&&tab)) die("hit column count");
        if(tab) *tab=0;
        u128 v;
        if(!dec128(p,&v)) die("hit decimal grammar");
        if(j<7) { if(v>bounds[j]) die("hit word bound"); h->x[j]=(uint64_t)v; }
        else if(j==7) { if(v>MAX_D7) die("hit wide operand bound"); h->x7=v; }
        else if(j==8) { if(v>MAX_D8) die("hit wide bound"); h->x8=v; }
        else { if(!v||v>MAX_ROOT) die("root bound"); h->root=v; }
        if(tab) p=tab+1;
    }
    if(h->x[0]<2||!h->x[1]) die("hit positive domain");
}
typedef struct {
    uint64_t start,end,segments,threads;
    char src_hash[65],make_hash[65],bin_hash[65],cfg_hash[65],base_hash[65];
    char *base;
    size_t base_len,base_n;
    uint64_t *base_v;
} Config;
typedef struct {
    uint64_t id,low,high,frontier,elapsed_ns,fallbacks;
    Hit *hits; size_t nhit,cap;
} Segment;
static void free_seg(Segment *s) { free(s->hits); memset(s,0,sizeof *s); }
static bool push_hit(Segment *s,Hit h) {
    if(s->nhit>=HIT_GUARD) return false;
    if(s->nhit==s->cap) {
        size_t next=s->cap?s->cap*2:8;
        if(next>HIT_GUARD) next=(size_t)HIT_GUARD;
        if(next<=s->cap||next>SIZE_MAX/sizeof(Hit)) die("hit allocation width");
        Hit *p=realloc(s->hits,next*sizeof(Hit));
        if(!p) return false;
        s->hits=p; s->cap=next;
    }
    s->hits[s->nhit++]=h; return true;
}
static uint64_t blocks(const Config *c) { return (c->end-c->start)/BLOCK+1; }
static void config_domain(const Config *c) {
    if(c->start<2||c->end<c->start||c->end>CAP||!c->segments||
       c->segments>MAX_SEGMENTS||c->segments>blocks(c)||!c->threads||
       c->threads>MAX_THREADS) die("configuration domain");
}
static void seg_bounds(const Config *c,uint64_t id,uint64_t *lo,uint64_t *hi) {
    if(id>=c->segments) die("segment ID domain");
    u128 k=blocks(c),a=(u128)id*k/c->segments,b=((u128)id+1)*k/c->segments;
    u128 l=c->start+a*BLOCK,h=c->start+b*BLOCK-1;
    if(h>c->end) h=c->end;
    if(l>h||h>CAP) die("partition width");
    *lo=(uint64_t)l; *hi=(uint64_t)h;
}
static uint64_t completed_blocks(const Segment *s) {
    return (s->frontier-s->low+1+BLOCK-1)/BLOCK;
}
static void state_name(char out[32],uint64_t id,const char *ext) {
    if(id>=MAX_SEGMENTS) die("segment filename domain");
    snprintf(out,32,"s%03" PRIu64 ".%s",id,ext);
}
static void own_dir(char exe[MAX_PATH]) {
    ssize_t n=readlink("/proc/self/exe",exe,MAX_PATH-1);
    if(n<1||n>=MAX_PATH-1) sysdie("executable path");
    exe[n]=0;
}
static void own_identity(char src[65],char make[65],char bin[65]) {
    char exe[MAX_PATH],path[MAX_PATH]; own_dir(exe); hash_file(exe,bin);
    char *slash=strrchr(exe,'/'); if(!slash) die("executable parent"); *slash=0;
    path2(path,exe,"a249110.c"); hash_file(path,src);
    path2(path,exe,"Makefile"); hash_file(path,make);
    if(strcmp(src,A249110_SOURCE_SHA)||strcmp(make,A249110_MAKE_SHA))
        die("binary not bound to neighboring source and Makefile");
}
static void check_identity(const Config *c) {
    char a[65],b[65],d[65]; own_identity(a,b,d);
    if(strcmp(a,c->src_hash)||strcmp(b,c->make_hash)||strcmp(d,c->bin_hash))
        die("source/build/binary changed");
}
static void free_cfg(Config *c) { free(c->base); free(c->base_v); }
/* Config baseline is parsed with a closed ASCII grammar, preserving its bytes. */
static void baseline_read(FILE *f,Config *c) {
    char *line=NULL; size_t cap=0,used=0,n=0;
    c->base=malloc((size_t)BASE_BYTES+1);
    c->base_v=malloc((size_t)HIT_GUARD*sizeof(uint64_t));
    if(!c->base||!c->base_v) die("baseline allocation");
    uint64_t prev=0;
    for(;;) {
        if(!read_line(f,&line,&cap)) die("baseline missing final blank record");
        size_t len=strlen(line);
        if(used+len+1>BASE_BYTES) die("baseline byte guard");
        memcpy(c->base+used,line,len); used+=len; c->base[used++]='\n';
        if(!len) break;
        if(n>=HIT_GUARD) die("baseline row guard");
        char *space=strchr(line,' '); uint64_t index,v;
        if(!space||strchr(space+1,' ')) die("baseline row shape");
        *space=0;
        if(!dec64(line,&index)||index!=n+1||!dec64(space+1,&v)||v<2||v>CAP||v<=prev)
            die("baseline index/value domain");
        c->base_v[n++]=v; prev=v;
    }
    static const uint64_t admitted[]={4,27,3125,398747,823543};
    if(n<5) die("baseline omits admitted prefix");
    for(unsigned j=0;j<5;++j) if(c->base_v[j]!=admitted[j]) die("baseline prefix mismatch");
    /* Exact scalar positive checks do not independently certify inherited gaps. */
    Scratch sc; scratch_init(&sc);
    for(size_t j=0;j<n;++j) {
        bool fb=false; u128 d;
        if(!derivative64(c->base_v[j],&d,&fb)||d>bounds[1]||
           predicate(c->base_v[j],(uint64_t)d,NULL,&fb,&sc)!=1) die("baseline nonmember");
    }
    scratch_clear(&sc); free(line); c->base_len=used; c->base_n=n; c->base[used]=0;
}
/* Hash memory through EVP, same SHA-256 definition as the streaming helper. */
static void hash_bytes(const void *data,size_t len,char out[65]) {
    unsigned char d[32]; unsigned int n=0;
    if(EVP_Digest(data,len,d,&n,EVP_sha256(),NULL)!=1||n!=32) die("hash memory");
    for(unsigned j=0;j<32;++j) snprintf(out+2*j,3,"%02x",(unsigned)d[j]);
}
/* Fixed temporary stems, exclusive creation; config+one state or two aggregates. */
static void temp_name(char out[32],const char *base) {
    const char *dot=strchr(base,'.'); size_t n=dot?(size_t)(dot-base):strlen(base);
    if(n>8) die("temporary stem");
    memcpy(out,base,n); memcpy(out+n,".tmp",5);
}
static FILE *atomic_begin(const char *dir,const char *base,char tmp[MAX_PATH]) {
    char name[32]; temp_name(name,base); path2(tmp,dir,name);
    int fd=open(tmp,O_CREAT|O_EXCL|O_RDWR|O_NOFOLLOW,0600);
    if(fd<0) sysdie("create temporary");
    FILE *f=fdopen(fd,"w+"); if(!f) sysdie("fdopen temporary"); return f;
}
static void durable(FILE *f) {
    if(fflush(f)||ferror(f)) sysdie("flush temporary");
    if(fsync(fileno(f))) sysdie("fsync temporary");
}
static void publish(const char *tmp,const char *dir,const char *base,bool replace) {
    char path[MAX_PATH]; path2(path,dir,base);
    if(replace) { if(!exists(path)) die("replacement target missing"); if(rename(tmp,path)) sysdie("rename"); }
    else { if(link(tmp,path)) sysdie("no-clobber publish"); if(unlink(tmp)) sysdie("unlink published temporary"); }
    sync_dir(dir);
}
static void atomic_end(FILE *f,const char *tmp,const char *dir,const char *base,bool replace) {
    durable(f); if(fclose(f)) sysdie("close temporary"); publish(tmp,dir,base,replace);
}
static void cfg_write(FILE *f,const Config *c) {
    if(fprintf(f,"A249110-CFG\nlow\t%" PRIu64 "\nhigh\t%" PRIu64
      "\nblock\t%" PRIu64 "\nsegments\t%" PRIu64 "\nworkers\t%" PRIu64
      "\nsource_sha\t%s\nmakefile_sha\t%s\nbinary_sha\t%s\n"
      "gmp\t%s\nopenssl\t%s\nopenmp\t%d\n",
      c->start,c->end,BLOCK,c->segments,c->threads,c->src_hash,c->make_hash,c->bin_hash,
      gmp_version,OpenSSL_version(OPENSSL_VERSION),_OPENMP)<0) sysdie("write config");
    for(unsigned j=0;j<9;++j) {
        char v[40]; fmt128(chain_bound(j),v);
        if(fprintf(f,"bound%u\t%s\n",j,v)<0) sysdie("write bound");
    }
    char r[40]; fmt128(MAX_ROOT,r);
    if(fprintf(f,"rootmax\t%s\nbaseline_sha\t%s\nbaseline\n",r,c->base_hash)<0||
       fwrite(c->base,1,c->base_len,f)!=c->base_len||fputs("endbase\n",f)==EOF) sysdie("write baseline");
}
static void config_load(const char *dir,Config *c) {
    char path[MAX_PATH],*line=NULL,*v; size_t cap=0;
    path2(path,dir,"run.cfg"); FILE *f=input(path);
    if(!read_line(f,&line,&cap)||strcmp(line,"A249110-CFG")) die("config magic");
    c->start=field64(f,&line,&cap,"low"); c->end=field64(f,&line,&cap,"high");
    if(field64(f,&line,&cap,"block")!=BLOCK) die("block mismatch");
    c->segments=field64(f,&line,&cap,"segments"); c->threads=field64(f,&line,&cap,"workers");
    config_domain(c);
    fieldhash(f,&line,&cap,"source_sha",c->src_hash);
    fieldhash(f,&line,&cap,"makefile_sha",c->make_hash);
    fieldhash(f,&line,&cap,"binary_sha",c->bin_hash);
    expect_key(f,&line,&cap,"gmp",&v); if(strcmp(v,gmp_version)) die("GMP mismatch");
    expect_key(f,&line,&cap,"openssl",&v); if(strcmp(v,OpenSSL_version(OPENSSL_VERSION))) die("OpenSSL mismatch");
    if(field64(f,&line,&cap,"openmp")!=_OPENMP) die("OpenMP mismatch");
    for(unsigned j=0;j<9;++j) {
        char key[16]; u128 z; snprintf(key,sizeof key,"bound%u",j);
        expect_key(f,&line,&cap,key,&v);
        if(!dec128(v,&z)||z!=chain_bound(j)) die("bound mismatch");
    }
    u128 root; expect_key(f,&line,&cap,"rootmax",&v);
    if(!dec128(v,&root)||root!=MAX_ROOT) die("root bound mismatch");
    fieldhash(f,&line,&cap,"baseline_sha",c->base_hash);
    if(!read_line(f,&line,&cap)||strcmp(line,"baseline")) die("baseline delimiter");
    baseline_read(f,c);
    char sha[65]; hash_bytes(c->base,c->base_len,sha);
    if(strcmp(sha,c->base_hash)) die("baseline hash mismatch");
    if(!read_line(f,&line,&cap)||strcmp(line,"endbase")) die("baseline end delimiter");
    expect_eof(f,"extra config record"); free(line); if(fclose(f)) sysdie("close config");
    hash_file(path,c->cfg_hash);
}
static void write_seg(const char *dir,const Config *c,const Segment *s,bool replace) {
    char name[32],tmp[MAX_PATH],row[256]; state_name(name,s->id,"tsv");
    FILE *f=atomic_begin(dir,name,tmp);
    if(fprintf(f,"A249110-STATE\ncfg_sha\t%s\nid\t%" PRIu64
       "\nlow\t%" PRIu64 "\nhigh\t%" PRIu64 "\nfrontier\t%" PRIu64
       "\nblocks\t%" PRIu64 "\nelapsed_ns\t%" PRIu64 "\nfallbacks\t%" PRIu64
       "\nhits\t%zu\n",c->cfg_hash,s->id,s->low,s->high,s->frontier,
       completed_blocks(s),s->elapsed_ns,s->fallbacks,s->nhit)<0) sysdie("write state");
    for(size_t j=0;j<s->nhit;++j) {
        (void)hit_text(&s->hits[j],row);
        if(fputs("hit\t",f)==EOF||fputs(row,f)==EOF) sysdie("write state hit");
    }
    if(fflush(f)) sysdie("flush state prefix");
    off_t length=ftello(f); if(length<0) sysdie("state offset");
    char sha[65]; hash_file_prefix(tmp,length,sha);
    if(fprintf(f,"state_sha\t%s\n",sha)<0) sysdie("write state hash");
    atomic_end(f,tmp,dir,name,replace);
}
static void read_seg(const char *dir,const Config *c,uint64_t id,Segment *s) {
    memset(s,0,sizeof *s);
    char name[32],path[MAX_PATH],*line=NULL; size_t cap=0;
    state_name(name,id,"tsv"); path2(path,dir,name); FILE *f=input(path);
    struct stat st; if(fstat(fileno(f),&st)) sysdie("state size");
    if(st.st_size<75||st.st_size>(off_t)(HIT_GUARD*STATE_HIT_MAX+4096)) die("state byte bound");
    off_t prefix=st.st_size-75;
    if(fseeko(f,prefix,SEEK_SET)) sysdie("seek footer");
    char footer[75],actual[65],recorded[65];
    if(fread(footer,1,75,f)!=75||memcmp(footer,"state_sha\t",10)||footer[74]!='\n') die("state footer shape");
    memcpy(recorded,footer+10,64); recorded[64]=0;
    if(!valid_hash(recorded)) die("state hash shape");
    hash_stream_prefix(f,prefix,actual); if(strcmp(actual,recorded)) die("state hash mismatch");
    if(fseeko(f,0,SEEK_SET)) sysdie("seek state");
    if(!read_line(f,&line,&cap)||strcmp(line,"A249110-STATE")) die("state magic");
    fieldhash(f,&line,&cap,"cfg_sha",actual); if(strcmp(actual,c->cfg_hash)) die("state config mismatch");
    s->id=field64(f,&line,&cap,"id"); if(s->id!=id) die("state id mismatch");
    s->low=field64(f,&line,&cap,"low"); s->high=field64(f,&line,&cap,"high");
    s->frontier=field64(f,&line,&cap,"frontier");
    uint64_t units=field64(f,&line,&cap,"blocks");
    s->elapsed_ns=field64(f,&line,&cap,"elapsed_ns");
    s->fallbacks=field64(f,&line,&cap,"fallbacks");
    uint64_t count=field64(f,&line,&cap,"hits"),lo,hi; seg_bounds(c,id,&lo,&hi);
    if(s->low!=lo||s->high!=hi||s->frontier<lo-1||s->frontier>hi||
       (s->frontier!=hi&&(s->frontier-lo+1)%BLOCK)||
       count>HIT_GUARD||count>s->frontier-lo+1||count>(uint64_t)prefix/24||
       units!=completed_blocks(s)||s->fallbacks>s->frontier-lo+1) die("state bounds/counts");
    if(s->frontier==lo-1&&(s->elapsed_ns||s->fallbacks)) die("unstarted counters");
    for(uint64_t j=0;j<count;++j) {
        if(!read_line(f,&line,&cap)||strncmp(line,"hit\t",4)) die("state hit prefix");
        Hit h; parse_hit(line+4,&h);
        if(h.x[0]<lo||h.x[0]>s->frontier||
           (s->nhit&&h.x[0]<=s->hits[s->nhit-1].x[0])) die("state hit order");
        if(!push_hit(s,h)) die("state hit resource guard");
    }
    if(ftello(f)!=prefix) die("state footer boundary");
    free(line); if(fclose(f)) sysdie("close state");
}
static bool sealed(const char *dir,uint64_t id) {
    char name[32],path[MAX_PATH]; state_name(name,id,"sha"); path2(path,dir,name); return exists(path);
}
static void check_seal(const char *dir,uint64_t id) {
    char name[32],path[MAX_PATH],sha[65],*line=NULL; size_t cap=0;
    state_name(name,id,"tsv"); path2(path,dir,name); hash_file(path,sha);
    state_name(name,id,"sha"); path2(path,dir,name); FILE *f=input(path);
    if(!read_line(f,&line,&cap)||!valid_hash(line)||strcmp(sha,line)) die("seal mismatch");
    expect_eof(f,"extra seal record"); free(line); if(fclose(f)) sysdie("close seal");
}
static void seal_segment(const char *dir,const Segment *s) {
    if(s->frontier!=s->high) die("incomplete state cannot be sealed");
    if(sealed(dir,s->id)) { check_seal(dir,s->id); return; }
    char name[32],path[MAX_PATH],tmp[MAX_PATH],sha[65];
    state_name(name,s->id,"tsv"); path2(path,dir,name); hash_file(path,sha);
    state_name(name,s->id,"sha"); FILE *f=atomic_begin(dir,name,tmp);
    if(fprintf(f,"%s\n",sha)<0) sysdie("write seal");
    atomic_end(f,tmp,dir,name,false);
}
static bool equal_record(const char *line,const char *expected) {
    size_t n=strlen(expected); return n&&expected[n-1]=='\n'&&strlen(line)==n-1&&!memcmp(line,expected,n-1);
}
static void compare_line(FILE *f,const char *expected) {
    char *line=NULL; size_t cap=0;
    if(!read_line(f,&line,&cap)||!equal_record(line,expected)) die("aggregate header mismatch");
    free(line);
}
static const char *const aggregate_files[]={"man.tsv","hits.tsv"};
static const char *const aggregate_magic[]={"A249110-MAN","A249110-HITS"};
static const char *const aggregate_columns[]={"id\tlow\thigh\tblocks\tstate_sha\telapsed_ns\tfallbacks\thits\n",
    "n\tx1\tx2\tx3\tx4\tx5\tx6\tx7\tx8\tR\n"};
/* Compare survivors against the authoritative stream; EOF only at a sealed
   segment boundary is a recoverable old prefix, never a truncated hit subset. */
static bool aggregates(const char *dir,const Config *c,uint64_t count,bool write) {
    FILE *f[2]={NULL,NULL}; char tmp[2][MAX_PATH]; bool ended[2]={false,false},missing=false;
    size_t seen[2]={0,0},boundary[2]={0,0};
    for(unsigned k=0;k<2;++k) {
        char path[MAX_PATH],header[128]; path2(path,dir,aggregate_files[k]);
        int n=snprintf(header,sizeof header,"%s\tcfg_sha=%s\n",aggregate_magic[k],c->cfg_hash);
        if(n<0||n>=(int)sizeof header) die("aggregate header bound");
        if(write) {
            f[k]=atomic_begin(dir,aggregate_files[k],tmp[k]);
            if(fputs(header,f[k])==EOF||fputs(aggregate_columns[k],f[k])==EOF) sysdie("write aggregate header");
        } else if(exists(path)) {
            f[k]=input(path); compare_line(f[k],header); compare_line(f[k],aggregate_columns[k]);
        } else { ended[k]=true; missing=true; }
    }
    for(uint64_t id=0;id<count;++id) {
        Segment s; read_seg(dir,c,id,&s); char row[256],sha[65],name[32],path[MAX_PATH];
        state_name(name,id,"tsv"); path2(path,dir,name); hash_file(path,sha);
        int n=snprintf(row,sizeof row,"%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
          "\t%s\t%" PRIu64 "\t%" PRIu64 "\t%zu\n",id,s.low,s.high,completed_blocks(&s),sha,s.elapsed_ns,s.fallbacks,s.nhit);
        if(n<0||n>=(int)sizeof row) die("manifest record bound");
        for(unsigned k=0;k<2;++k) {
            boundary[k]=seen[k];
            size_t rows=k?s.nhit:1;
            for(size_t j=0;j<rows;++j) {
                if(k) (void)hit_text(&s.hits[j],row);
                if(write) { if(fputs(row,f[k])==EOF) sysdie("write aggregate row"); }
                else if(!ended[k]) {
                    char *line=NULL; size_t cap=0;
                    if(!read_line(f[k],&line,&cap)) {
                        ended[k]=true;
                        if(seen[k]!=boundary[k]) die("aggregate ends within segment");
                    } else {
                        if(!equal_record(line,row)) die("corrupt/foreign/nonprefix aggregate");
                        ++seen[k];
                    }
                    free(line);
                }
            }
        }
        free_seg(&s);
    }
    for(unsigned k=0;k<2;++k) {
        char path[MAX_PATH]; path2(path,dir,aggregate_files[k]);
        if(write) atomic_end(f[k],tmp[k],dir,aggregate_files[k],exists(path));
        else if(f[k]) { expect_eof(f[k],"extra aggregate row"); if(fclose(f[k])) sysdie("close aggregate"); }
    }
    return missing||ended[0]||ended[1];
}
static bool state_filename(const char *name,uint64_t *id,const char **ext) {
    if(strlen(name)!=8||name[0]!='s'||name[4]!='.') return false;
    uint64_t v=0;
    for(unsigned j=1;j<=3;++j) { if(name[j]<'0'||name[j]>'9') return false; v=10*v+(unsigned)(name[j]-'0'); }
    if(strcmp(name+5,"tsv")&&strcmp(name+5,"sha")&&strcmp(name+5,"tmp")) return false;
    *id=v; *ext=name+5; return true;
}
/* Inventory is read-only until all authority and surviving aggregates pass. */
static void inventory(const char *dir,const Config *c,bool clean) {
    DIR *d=opendir(dir); if(!d) sysdie("inventory directory"); unsigned temps=0; bool changed=false;
    for(;;) {
        errno=0; struct dirent *e=readdir(d);
        if(!e) { if(errno) sysdie("readdir"); break; }
        const char *n=e->d_name;
        if(!strcmp(n,".")||!strcmp(n,"..")) continue;
        uint64_t id=0; const char *ext=NULL;
        bool state=state_filename(n,&id,&ext);
        bool temp=!strcmp(n,"run.tmp")||!strcmp(n,"man.tmp")||!strcmp(n,"hits.tmp")||(state&&!strcmp(ext,"tmp"));
        if(state&&id>=c->segments) die("foreign segment file");
        if(!state&&!temp&&strcmp(n,"run.cfg")&&strcmp(n,"man.tsv")&&strcmp(n,"hits.tsv")) die("foreign artifact");
        char path[MAX_PATH]; path2(path,dir,n); if(!exists(path)) die("disappearing artifact");
        if(temp) {
            if(++temps>2) die("temporary artifact budget");
            if(clean) { if(unlink(path)) sysdie("remove audited stale temporary"); changed=true; }
        }
    }
    if(closedir(d)) sysdie("close inventory");
    if(changed) sync_dir(dir);
}
typedef struct { uint64_t sealed,frontier,hits,fallbacks; u128 elapsed; Segment open; bool has_open; } Audit;
static void baseline_match(const Config *c,const Segment *s) {
    size_t j=0;
    while(j<c->base_n&&c->base_v[j]<s->low) ++j;
    size_t h=0;
    while(j<c->base_n&&c->base_v[j]<=s->frontier) {
        if(h>=s->nhit||s->hits[h].x[0]!=c->base_v[j]) die("coverage differs from baseline");
        ++h; ++j;
    }
    if(h<s->nhit&&s->hits[h].x[0]<=c->base_v[c->base_n-1]) die("extra hit inside admitted baseline");
}
static Audit audit(const char *dir,const Config *c) {
    Audit a={.frontier=c->start-1}; bool open_seen=false;
    inventory(dir,c,false);
    for(uint64_t id=0;id<c->segments;++id) {
        Segment s; read_seg(dir,c,id,&s); bool seal=sealed(dir,id);
        if(open_seen) {
            if(seal||s.frontier!=s.low-1||s.nhit||s.elapsed_ns||s.fallbacks) die("future state advanced");
        } else {
            if(s.low!=a.frontier+1) die("coverage gap/overlap");
            baseline_match(c,&s);
            for(size_t j=0;j<s.nhit;++j) if(!verified_hit(&s.hits[j])) die("invalid positive witness");
            if(s.nhit>HIT_GUARD-a.hits) die("global hit guard");
            a.hits+=s.nhit; a.elapsed+=s.elapsed_ns;
            if(s.fallbacks>UINT64_MAX-a.fallbacks) die("fallback counter overflow");
            a.fallbacks+=s.fallbacks; a.frontier=s.frontier;
            if(seal) {
                if(s.frontier!=s.high) die("premature seal");
                check_seal(dir,id); ++a.sealed;
            } else { a.open=s; a.has_open=true; open_seen=true; continue; }
        }
        free_seg(&s);
    }
    return a;
}
typedef struct { uint32_t *v; size_t n; } Primes;
static Primes make_primes(uint64_t high) {
    uint64_t root=isqrt64(high); if(root>223606) die("prime table bound");
    size_t len=(size_t)root+1; uint8_t *mark=calloc(len,1);
    Primes p={.v=malloc(len*sizeof(uint32_t))};
    if(!mark||!p.v) die("prime allocation");
    for(uint64_t a=2;a<=root/a;++a) if(!mark[a])
        for(uint64_t q=a*a;q<=root;q+=a) mark[q]=1;
    for(uint64_t a=2;a<=root;++a) if(!mark[a]) p.v[p.n++]=(uint32_t)a;
    free(mark); return p;
}
static bool block_scan(const Config *c,const Primes *pr,Segment *s,uint64_t low,uint64_t high,
                        uint64_t other_hits,uint64_t *fallbacks) {
    size_t width=(size_t)(high-low+1),saved=s->nhit;
    if(low<2||high<low||width>BLOCK) die("block bounds");
    uint64_t *rem=malloc(width*sizeof(uint64_t)),*d1=calloc(width,sizeof(uint64_t));
    uint8_t *flags=malloc(width);
    if(!rem||!d1||!flags) { free(rem); free(d1); free(flags); return false; }
    for(size_t i=0;i<width;++i) rem[i]=low+i;
    for(size_t j=0;j<pr->n&&!stop_requested();++j) {
        uint64_t p=pr->v[j]; if(p>high/p) break;
        u128 first=((u128)low+p-1)/p*p;
        for(uint64_t v=(uint64_t)first;v<=high;) {
            size_t i=(size_t)(v-low); unsigned e=0;
            while(rem[i]%p==0) { rem[i]/=p; ++e; }
            u128 add=(u128)e*(v/p);
            if(add>bounds[1]-d1[i]) die("sieve sum width");
            d1[i]+=(uint64_t)add;
            if(high-v<p) break;
            v+=p;
        }
    }
    for(size_t i=0;i<width;++i) if(rem[i]>1) {
        uint64_t add=(low+i)/rem[i];
        if(add>bounds[1]-d1[i]) die("sieve residual width");
        d1[i]+=add;
    }
    uint64_t fb=0;
#pragma omp parallel num_threads((int)c->threads) reduction(+:fb)
    {
        Scratch sc; scratch_init(&sc);
#pragma omp for schedule(dynamic,64)
        for(size_t i=0;i<width;++i) {
            active_input=low+i; if((i&4095)==0) heartbeat(0);
            if(stop_requested()) { flags[i]=2; continue; }
            bool fallback=false;
            int result=predicate(low+i,d1[i],NULL,&fallback,&sc);
            if(fallback) ++fb;
            flags[i]=(stop_requested()||result<0)?2:(result?1:0);
        }
        scratch_clear(&sc);
    }
    *fallbacks=fb;
    bool complete=!stop_requested();
    for(size_t i=0;i<width;++i) if(flags[i]==2) complete=false;
    if(complete) {
        Scratch sc; scratch_init(&sc);
        for(size_t i=0;i<width;++i) if(flags[i]==1) {
            bool fallback=false; Hit h;
            if(stop_requested()||other_hits+s->nhit>=HIT_GUARD||
               predicate(low+i,d1[i],&h,&fallback,&sc)!=1||!push_hit(s,h)) { complete=false; break; }
        }
        scratch_clear(&sc);
    }
    if(stop_requested()) complete=false;
    if(complete) s->frontier=high; else s->nhit=saved;
    free(rem); free(d1); free(flags); return complete;
}
static bool disk_room(const char *dir) {
    struct statvfs v; if(statvfs(dir,&v)) sysdie("statvfs");
    return (u128)v.f_bavail*v.f_frsize>=UINT64_C(1000000000);
}
static int lock_run(const char *dir,bool exclusive) {
    /* Remove trailing slashes only for lstat: a final symlink is never a run. */
    char root[MAX_PATH]; size_t len=strlen(dir);
    if(!len||len>=sizeof root) die("run directory path domain");
    memcpy(root,dir,len+1);
    while(len>1&&root[len-1]=='/') root[--len]=0;
    struct stat dst;
    if(lstat(root,&dst)) sysdie("stat run directory");
    if(!S_ISDIR(dst.st_mode)) die("non-directory/symlink run root");
    char path[MAX_PATH]; path2(path,dir,"run.cfg");
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK); if(fd<0) sysdie("open config lock");
    struct stat st; if(fstat(fd,&st)) sysdie("stat lock");
    if(!S_ISREG(st.st_mode)) die("nonregular config lock");
    if(flock(fd,(exclusive?LOCK_EX:LOCK_SH)|LOCK_NB)) sysdie("run busy/lock failure");
    return fd;
}
static int do_init(int argc,char **argv) {
    if(argc!=7) die("usage: a249110 init DIR LOW HIGH SEGMENTS WORKERS");
    Config c={0};
    if(!dec64(argv[3],&c.start)||!dec64(argv[4],&c.end)||
       !dec64(argv[5],&c.segments)||!dec64(argv[6],&c.threads)) die("decimal CLI grammar");
    config_domain(&c); own_identity(c.src_hash,c.make_hash,c.bin_hash);
    char exe[MAX_PATH],path[MAX_PATH]; own_dir(exe);
    char *slash=strrchr(exe,'/'); if(!slash) die("executable parent"); *slash=0;
    path2(path,exe,"../data/b249110.txt"); FILE *bf=input(path);
    baseline_read(bf,&c); expect_eof(bf,"extra baseline data"); if(fclose(bf)) sysdie("close baseline");
    hash_bytes(c.base,c.base_len,c.base_hash);
    char probe[MAX_PATH]; path2(probe,argv[2],"s255.tmp");
    if(mkdir(argv[2],0700)) sysdie("create private new run directory");
    path2(probe,argv[2],".."); sync_dir(probe);
    if(!disk_room(argv[2])) die("disk reservation below 1 GB");
    char tmp[MAX_PATH]; FILE *f=atomic_begin(argv[2],"run.cfg",tmp);
    if(flock(fileno(f),LOCK_EX|LOCK_NB)) sysdie("lock initial config inode");
    cfg_write(f,&c); durable(f); hash_file(tmp,c.cfg_hash);
    for(uint64_t id=0;id<c.segments;++id) {
        Segment s={.id=id}; seg_bounds(&c,id,&s.low,&s.high); s.frontier=s.low-1;
        write_seg(argv[2],&c,&s,false);
    }
    /* The lock remains on the same inode across publication and headers. */
    publish(tmp,argv[2],"run.cfg",false);
    (void)aggregates(argv[2],&c,0,true);
    if(fclose(f)) sysdie("close init lock");
    fprintf(stderr,"INIT A249110 target=[%" PRIu64 ",%" PRIu64 "] segments=%" PRIu64
        " workers=%" PRIu64 " blocks=%" PRIu64 " cfg_sha=%s\n",c.start,c.end,c.segments,c.threads,blocks(&c),c.cfg_hash);
    free_cfg(&c); return 0;
}
static int do_status(const char *dir,bool verify) {
    int lock=lock_run(dir,false); Config c={0}; config_load(dir,&c); check_identity(&c);
    Audit a=audit(dir,&c); bool short_derived=aggregates(dir,&c,a.sealed,false);
    char elapsed[40]; fmt128(a.elapsed,elapsed);
    printf("A249110 %s target=[%" PRIu64 ",%" PRIu64 "] sealed=%" PRIu64
        "/%" PRIu64 " frontier=%" PRIu64 " remaining=%" PRIu64 " hits=%" PRIu64
        " saved_ns=%s derived=%s\n",verify?"VERIFY":"STATUS",c.start,c.end,a.sealed,
        c.segments,a.frontier,c.end-a.frontier,a.hits,elapsed,short_derived?"MISSING_OR_PREFIX":"CURRENT");
    bool done=a.sealed==c.segments;
    puts(done&&!short_derived?"DONE":"INCOMPLETE");
    free_seg(&a.open); free_cfg(&c); if(close(lock)) sysdie("close read lock");
    return short_derived||(verify&&!done)?2:0;
}
static int do_next(const char *dir) {
    uint64_t begin=ns_now(); int lock=lock_run(dir,true);
    Config c={0}; config_load(dir,&c); check_identity(&c); Audit a=audit(dir,&c);
    bool oldprefix=aggregates(dir,&c,a.sealed,false);
    inventory(dir,&c,true);
    if(oldprefix) (void)aggregates(dir,&c,a.sealed,true);
    if(!a.has_open) {
        puts("DONE: all segments sealed; no enumeration"); free_cfg(&c);
        if(close(lock)) sysdie("close lock");
        return 0;
    }
    Segment s=a.open; uint64_t other=a.hits-s.nhit;
    if(s.frontier==s.high) {
        seal_segment(dir,&s); (void)aggregates(dir,&c,a.sealed+1,true);
        fprintf(stderr,"CLOSED recovered_complete segment=%" PRIu64 " no_enumeration\n",s.id);
        free_seg(&s); free_cfg(&c); if(close(lock)) sysdie("close lock");
        return 0;
    }
    live_target=c.end; live_segment=s.id; live_segments=c.segments; live_frontier=s.frontier;
    live_units=completed_blocks(&s); live_fallbacks=s.fallbacks; live_begin=begin; live_enabled=true;
    if(begin>UINT64_MAX-UINT64_C(10000000000)) die("heartbeat time width");
    atomic_store_explicit(&next_note,begin+UINT64_C(10000000000),memory_order_relaxed);
    fprintf(stderr,"START A249110 target=%" PRIu64 " segment=%" PRIu64 "/%" PRIu64
      " range=[%" PRIu64 ",%" PRIu64 "] frontier=%" PRIu64 " workers=%" PRIu64
      " active_input=%" PRIu64 " factor_operand=0 cfg_sha=%s\n",c.end,s.id,c.segments,
      s.frontier+1,s.high,s.frontier,c.threads,s.frontier+1,c.cfg_hash);
    Primes pr=make_primes(s.high); bool incomplete=false; uint64_t attempt_fb=0;
    const char *reason="SEGMENT_COMPLETE";
    while(s.frontier<s.high&&!stop_requested()) {
        if(!disk_room(dir)) { incomplete=true; reason="DISK_GUARD"; break; }
        uint64_t low=s.frontier+1,hi=low+BLOCK-1;
        if(hi>s.high) hi=s.high;
        live_frontier=s.frontier; live_units=completed_blocks(&s); live_fallbacks=s.fallbacks;
        uint64_t t=ns_now(),fb=0;
        bool complete=block_scan(&c,&pr,&s,low,hi,other,&fb);
        if(fb>UINT64_MAX-attempt_fb) die("attempt counter overflow");
        attempt_fb+=fb;
        if(!complete) { incomplete=true; reason=stop_requested()?"SIGNAL":"BLOCK_OR_RESOURCE_FAILURE"; break; }
        uint64_t now=ns_now(); if(now<t||now-t>UINT64_MAX-s.elapsed_ns) die("elapsed width");
        s.elapsed_ns+=now-t;
        if(fb>UINT64_MAX-s.fallbacks) die("fallback width");
        s.fallbacks+=fb;
        baseline_match(&c,&s); write_seg(dir,&c,&s,true);
    }
    live_enabled=false; free(pr.v);
    if(s.frontier==s.high&&!stop_requested()&&!incomplete) {
        seal_segment(dir,&s); (void)aggregates(dir,&c,a.sealed+1,true);
    } else { incomplete=true; if(stop_requested()) reason="SIGNAL"; }
    fprintf(stderr,"%s A249110 segment=%" PRIu64 " frontier=%" PRIu64
      " blocks=%" PRIu64 " hits=%zu attempted_fallback_inputs=%" PRIu64
      " wall_s=%.6f reason=%s active_input=0 factor_operand=0\n",incomplete?"INCOMPLETE":"CLOSED",
      s.id,s.frontier,completed_blocks(&s),s.nhit,attempt_fb,(double)(ns_now()-begin)/1e9,reason);
    free_seg(&s); free_cfg(&c); if(close(lock)) sysdie("close lock"); return incomplete?2:0;
}
int main(int argc,char **argv) {
    if(argc<2) die("usage: a249110 init|next|status|verify ...");
    int rc;
    if(!strcmp(argv[1],"init")) rc=do_init(argc,argv);
    else {
        if(argc!=3) die("usage: a249110 next|status|verify DIR");
        if(!strcmp(argv[1],"next")) {
            struct sigaction sa={0}; sa.sa_handler=on_signal; sa.sa_flags=SA_RESTART;
            sigemptyset(&sa.sa_mask);
            if(sigaction(SIGINT,&sa,NULL)||sigaction(SIGTERM,&sa,NULL)) sysdie("signal handler");
            rc=do_next(argv[2]);
        } else if(!strcmp(argv[1],"status")) rc=do_status(argv[2],false);
        else if(!strcmp(argv[1],"verify")) rc=do_status(argv[2],true);
        else die("unknown verb");
    }
    if(fflush(stdout)||ferror(stdout)||fflush(stderr)||ferror(stderr)) sysdie("flush output");
    return rc;
}
