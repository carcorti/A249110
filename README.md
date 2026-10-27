# OEIS A249110: exact enumeration and scaling structure

Carlo Corti — Independent researcher — carlo.corti@outlook.com

**Release v1.0.1, 27 October 2026.** This package adds the final manuscript
source and matching PDF to the source, data and evidence first released in v1.0.

Repository: <https://github.com/carcorti/A249110>.
Zenodo release-series DOI: <https://doi.org/10.5281/zenodo.23695423>.
This concept DOI identifies all versions; each deposited version has a distinct
DOI. Use the preferred article citation in `CITATION.cff` when citing the paper,
and specify the software version when referring to this computational package.
The initial v1.0 deposit is openly available as
<https://doi.org/10.5281/zenodo.23695424>. Its existence does not by itself certify
the files of a subsequent release.

## Definition and finite result

Let `D(0)=D(1)=0`. For `n>=2`, the ordinary arithmetic derivative is
`D(n)=sum(e*(n/p))` over prime powers `p^e || n`. Define `x0=n` and
`xj=D(x(j-1))` for `j=1,...,8`. A member satisfies
`x0^2+x1^2+...+x8^2=R^2` for a positive integer `R`.
There are nine squared chain coordinates and ten witness components including
the root. Offset is one. Zero tails are admitted; there is no primitivity,
family or strictly-positive-tail filter. `D` is not additive on sums.

The validated local indexed prefix is:

```text
1 4
2 27
3 3125
4 398747
5 823543
6 1072281223
7 1320016916
8 8910114183
9 10361580899
```

The first five ranks are inherited from the accepted OEIS baseline and their
membership is independently rechecked. Recorded new coverage is:

| Portion | Inclusive interval | Sealed segments | Hits |
|---|---|---:|---:|
| First run | 823544..1072281223 | 2 | 1 |
| Continuation's committed prefix | 1072281224..20246541959 | 29 | 3 |
| Final adjacent run | 20246541960..22000000000 | 3 | 0 |

The intervals join without gaps: 34 seals, 83921 committed blocks and
21999176457 newly classified inputs. The continuation retains its original
50000000000 target and is **INCOMPLETE** relative to it; its 45 unstarted
states contribute no coverage. The final run is **DONE**.

Subject to the inherited prefix, correct execution of the producer, the stated
finite-domain primality premises and complete records, there is no further
member through 22000000000 inclusive. Thus
`22000000000 < a(10) <= 285311670611 = 11^11`; `a(10)` is unknown.
The historical family `p^p` proves infinitude and supplies the unindexed upper
witness. Neither `11^11` nor another family witness is inserted as index ten.

The manuscript proves the complete integer scales of the five observed ordered
forms: two infinite classes with first coordinates `p^p` and `330004229*p^p`,
and three singleton scale classes. The latter assertion is for each fixed
form, not a classification of every possible shape. The family mechanism and
general rate theory are credited to their actual prior sources. The known
zero-tail witness `1072281223` predates this enumeration; its new claim here
is rank six. No density law is inferred from nine terms.

## Indispensable payload

| File or group | Concrete role |
|---|---|
| `src/a249110.c` | Exact reviewed and executed C source, with its stable original basename and bytes |
| `src/Makefile` | Same compiler/options/linkage; only the `check` recipe routes to the portable package checker |
| `data/b249110.txt` | Canonical contiguous indexed terms 1..9, 88 bytes |
| `data/a249110.txt` | Canonical documentary derivative/root table, 9 rows, 11 columns, 1029 bytes |
| `paper/A249110.tex`, `paper/A249110.pdf` | Final monolithic manuscript source and matching PDF, with internal bibliography; no external scientific fragments/assets/BibTeX |
| `paper/analyze.py` | Exact finite structural checker: forms, rates, depth examples, bounds and manifest totals |
| `check/records.py` | Original independent Python run-record/positive-witness auditor, byte-identical to its workspace source |
| `check/afile.py` | Original independent documentary/indexed-table arithmetic checker |
| `check/verify.py` | Portable package runner: integrity, safe restoration, data regeneration, retained-data checks and explicit optional native/development modes |
| `proof/map.json` | Complete archive/shared-input index: compact member, original/restored path, mode, size, SHA-256 and evidence role |
| `proof/run.tgz` | 122 original run files, exact historical Makefile and original executed binary: 124 members |
| `proof/dev.tgz` | Original development drivers/fixtures, frozen small/selected oracle tables and calibration protocol: 15 members |
| `proof/logs.tgz` | Essential final-identity development receipts, calibration records and corrected numeric/resource proof: 73 members |
| `proof/name.diff` | Exact two-line-to-one-line public Makefile check-routing transformation |
| `checks.sha256` | Frozen public-file inventory and byte identities, excluding itself |
| `LICENSE`, `CITATION.cff`, `.gitignore`, this README | Existing author MIT license, citation metadata, Git build exclusions and reproducible instructions |

The data-file columns are:

```text
b-file: i a(i)
a-file: i n D(n) D^2(n) D^3(n) D^4(n) D^5(n) D^6(n) D^7(n) D^8(n) root
```

In the a-file `n=a(i)`; the sequence index is not a witness component. Both
files are ASCII and end with exactly two LF bytes (one final empty record),
without CRLF or a third trailing LF. The a-file is documentary, not a sparse
list of later indexed terms. Its exclusion comment has the production
dependencies stated above. Neither inclusion here nor the file names assert
an OEIS attachment upload.

The manuscript source and PDF use the common stem `A249110`; there are no
external scientific TeX inputs or bibliography files. Historical code/run
identities and original receipt dates remain intact. The published Git control
file excludes generated build/editor products and retains both manuscript
files. No review packets, auxiliary TeX files or generated executable are part
of the payload.

## Retained-data verification

From the package root, with Python 3.11 or later (standard library only):

```sh
python3 -B check/verify.py
```

The command verifies the exact payload and all archive members, restores the
historical layout only in a private temporary root, binds the original source,
Makefile and binary to the saved configurations, checks each run, reconstructs
the positives by complete trial division and integer square roots, regenerates
the b-file from the embedded baseline plus ordered campaign hits, and regenerates
the a-file's numeric rows with the retained comment header and exact framing.
It also runs the unchanged structural checker, compares the TeX's five forms,
audits all eight original calibration arms separately from official coverage,
and regenerates the frozen 4095-input finite fixture byte for byte.

Expected result: exit 0, JSON `status: PASS`, 9 documentary rows, 72 derivative
identities, 9 square identities, 5 primitive forms and run states
`DONE / INCOMPLETE / DONE`. The original run checker's incomplete status is
expected, never repaired. No producer is called in this default mode. Read the
JSON scope fields: arithmetic/record checks are not a second negative census.

Hashes establish byte identity, not mathematical truth or historical execution.
The Python arithmetic shares the predicate and saved inputs with the producer
but uses different arithmetic code from its C/GMP/Miller–Rabin/rho path. The
native inclusion helper shares C code and is correlated implementation evidence.

## Build and optional bounded native verification

The producer targets **Linux LP64**, with `/proc/self/exe`, `flock`, GCC's unsigned
128-bit extension, C17, OpenMP, GMP and OpenSSL libcrypto. Build tools:
`gcc`, `make`, `sha256sum`, `cut`, GMP development headers and OpenSSL development
headers. On Debian/Ubuntu-family systems these are provided by `build-essential`,
`libgmp-dev` and `libssl-dev`.

```sh
make -C src
python3 -B check/verify.py native
```

The optional mode builds a fresh public executable in temporary storage, checks
259 distinct temporary candidates (a small interval and selected singleton
positive/zero-tail/real-wide cases), and compares outputs with complete Python
trial division. It separately runs read-only historical verification with the
archived original executable and its exact original neighbors: expected exits
`0,2,0`. The original binary is a preserved Linux x86-64 artifact; that part
requires a compatible runtime. Default pure-Python verification does not.

The public Makefile's `check` target invokes this same native mode. The source,
numerical algorithm, CLI, flags and linkage are preserved. The public Makefile
and fresh binary have distinct identities because of the check-routing change.
They are **not** attributed to the recorded campaigns: a direct fresh-public-build
attempt to verify a historical run must refuse its identity. The exact old
Makefile and binary are stored once in `run.tgz` and restored with the shared
unchanged source for historical verification.

`make -C src` creates the specifically generated `src/a249110`; `make -C src clean`
removes that build product. The checker recognizes only that exact generated
path as outside the frozen source inventory, in addition to root `.git` metadata.
Other unknown files/directories or changed/missing payload files are refused.
The handed-over directory contains no generated executable. Prefer the native
checker if all build products should stay temporary.

No full campaign is part of these commands. Any later production search requires
its own target/configuration, runtime/environment checks and operational decision.
Saved run configurations, states and seals must not be rewritten to use a new
binary or a different target.

## Development checks and evidence restoration

For the original bounded quick and wide suites, also install SymPy (tested
version 1.12) and use the native build dependencies above:

```sh
python3 -B check/verify.py dev
```

This performs the default/native checks and rebuilds the unchanged historical
recipe in a separate scratch tree before running `check.py --quick` and `wide.py`.
The latter supplies factor candidates through SymPy and checks recursive Lucas
`n-1` prime certificates, prime-factor products and selected wide C paths.
Finite output agreement and prime certificates have their documented operand
scope; they do not independently certify every negative in the campaign.

The full raw evidence can be inspected without executing the producer:

```sh
python3 -B check/verify.py restore /tmp/a249110-inspect
```

The destination must not exist and must be outside this package. `map.json`
maps compact archive names to original paths. It restores `runs/`, the exact
historical source/build/binary, `validation/`, fixture inputs and historical
receipt paths. Restoration does not execute scripts or run searches. Original
calibration archive members are restored below `outputs/rev5/calraw/`; their
original container/member names and modes remain in the index. All published
archive members have compact safe names; long historical paths exist only in
the disposable restored tree. Independent checkers and the C source are shared
with browsable public files instead of being duplicated in archives.

Original development drivers for operational faults, synthetic maximum-width
transport, toolchain/sanitizer controls and calibration are retained for method
inspection and supported expert replay. They are not automatically run by the
default checker. Calibration/tool drivers can write new scratch receipts and
require their historical tools. Original receipts are dated evidence, not
claims that all those tests were rerun during package preparation. Some include
intentional failure diagnostics and private temporary-path strings. Expected
refusals are not sequence terms. Failed first attempts are not promoted to PASS.

The original capacity driver also needed a third-party source file merely for
its provenance hash. It is not included as a purported standalone replay:
the self-contained published `analyze.py` recomputes the needed majorants, and
the original capacity receipt/corrected proof remain indexed. Obsolete bridge
drivers, pre-final code variants, duplicate logs, review conversations, editor
proposals and third-party book/paper copies are excluded. Mathematical sources
and exact versions are cited in the monolithic TeX; acquire external works from
those primary locators when reading the proofs. They are not TeX build inputs.

## Numerical, execution and chronology boundaries

Supported original inputs are at most 50000000000, distinct from completed
coverage through 22000000000. The universal chain bounds require 67 bits for
`x7`, 72 for `x8`/the root and 144 for the square sum. Coordinates are imported
into GMP before multiplication. Only `x1,...,x7` are irregularly factored;
`x8` is not factored. Rho is a bounded accelerator followed by exact trial
division; interruption/exhaustion means INCOMPLETE, never a negative answer.

Finite deterministic primality premises are external: Sinclair's seven bases
below `2^64`, and the first twelve prime bases strictly below
`318665857834031151167461` (Sorenson–Webster). The potentially wide factored
operand is below this threshold. The package does not re-establish either
exhaustive primality computation. See the manuscript's primary references.

Historical execution environment: AMD Ryzen 9 7940HS, eight physical cores,
sixteen logical processors, Linux Mint 22.3, kernel 6.17.0-42, GCC 13.3.0,
GMP 6.3.0, OpenSSL 3.0.13, sixteen workers, OpenMP macro 201511; Python 3.12.3
for retained independent checks. Raw environment, toolchain identities and
commands are indexed. No installed-memory, sustained RSS or thermal claim is
inferred beyond what the original receipts measure.

Saved completed-block work totals approximately 26595 seconds (about 7 h 23 min),
with portions about 914, 23332 and 2349 seconds. These counters exclude pauses,
checkpoint/audit overhead and repeated unfinished work; they are not full
campaign wall time or thread-seconds. Calibration has eight observations on
four windows with two worker counts; those repeated observations are not eight
disjoint interval searches and are not new indexed coverage.

Historical documents in the archives retain their dates and pre-campaign
statements (for example, five known ranks or no campaign yet). Current status is
the nine-row result above. Prior knowledge of `p^p` and the terminating witness,
the later consecutive-rank scans, the post-result 4/27 tuple observation and the
subsequent family proof are separate events. No old receipt is updated to
pretend it knew a later result.

## Manuscript build, license and attribution

Use a LaTeX installation with `pdflatex`, Latin Modern, Babel English, AMS math,
booktabs, geometry, xurl and hyperref. The PDF is already included. To rebuild
it while keeping auxiliary files outside the package, run from this root:

```sh
texcheck=$(mktemp -d)
pdflatex -interaction=nonstopmode -halt-on-error -output-directory="$texcheck" paper/A249110.tex
pdflatex -interaction=nonstopmode -halt-on-error -output-directory="$texcheck" paper/A249110.tex
```

The rebuilt PDF is `$texcheck/A249110.pdf`; inspect the final log for warnings.
No BibTeX, `.bib`, `.bbl`, external scientific `input/include` or figures are
needed. The delivered PDF was checked for settled references, warning-free
compilation, embedded metadata, link destinations and page layout. Rebuilding
may change PDF byte identities because of engine versions or timestamps; the
SHA-256 manifest identifies the delivered bytes, not an arbitrary rebuild.
Copying a rebuilt PDF into this payload requires refreshing `checks.sha256` and
rechecking the complete package. `.gitignore` retains the delivered PDF and
source while excluding auxiliary/editor files and the local C executable.

The existing MIT `LICENSE` by Carlo Corti is preserved byte for byte. No license
grant is inferred for cited external works. The retained OEIS text snapshot
keeps its original contributor credits and OEIS End-User License Agreement
notice; it is not relicensed by the project's MIT license. The paper credits
Paolo P. Lava, Ray Chandler and the actual theoretical/software sources.
Luna / OpenAI Codex assisted with code, local checks, curation and writing;
Carlo Corti is the sole author and retains scientific responsibility. Code
review, manuscript review, positive reconstruction and record audit have the
distinct scopes described in the manuscript; model agreement is not a second
negative census.
