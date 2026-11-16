# Statistical battery runbook

Everything needed to run the external test batteries against the RNG-SDK and
return usable results. Written to be followed end to end without asking us a
question.

**Target: macOS** (Homebrew). Linux equivalents are given inline wherever they
differ — the only real differences are the package manager, `wget` vs `curl`,
and BSD vs GNU flags on `sed` and `nproc`. Where a command differs it is
marked **macOS** / **Linux**; everything unmarked works on both.

If the machine is an Apple Silicon Mac, say so in your write-up — an ARM64
result is worth more to us than another x86 one, because the spec asks for
results "across CPU architectures" and every number we have so far is x86.
Byte output is unaffected: ARM64 is little-endian like x86, so the
fingerprints in §2 must still match exactly.

Design rationale — what is tested and why, and why the crypto tier gets
shallow runs — is in
`docs/design/2026-08-18-statistical-batteries-design.md`.
Read it once before starting; it is short and it explains what the results
are for.

---

## 0. What you are running

Four independent test batteries consume a raw byte stream and look for
structure that a good generator would not have:

| Battery | Appetite | What it is good at |
|---|---|---|
| NIST SP 800-22 | ~125 MB | the regulator-recognised suite; 15 tests |
| Dieharder | tens of GB | Marsaglia classics; kills lattice-structured LCGs |
| TestU01 | 10^9 – 10^11 numbers | the academic standard; SmallCrush → Crush → BigCrush |
| PractRand | unbounded, doubling | long-range correlation the others stop too early to see |

Bytes come from `rng_stream`, built from this repo. It writes raw bytes to
stdout and nothing else; all diagnostics go to stderr, so piping it straight
into a battery is safe.

---

## 1. Build the SDK and the stream tool

**macOS** — compiler comes from the Command Line Tools; the rest from Homebrew
(install it from https://brew.sh if absent):

```bash
xcode-select --install          # no-op if already present
brew install cmake git
```

**Linux** (Ubuntu/Debian):

```bash
sudo apt update && sudo apt install -y build-essential cmake git
```

Then, on both — `JOBS` is used throughout instead of `nproc`, which does not
exist on macOS:

```bash
JOBS=$(getconf _NPROCESSORS_ONLN)

git clone <repo-url> rng-sdk && cd rng-sdk
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$JOBS"
./build/rng_tests          # must end with "PASSED: <n>/<n> checks"
```

The `ctr` source (AES-256-CTR-DRBG) needs the OpenSSL backend. macOS ships
LibreSSL as `/usr/bin/openssl`, which is **not** what we want — install real
OpenSSL 3 and point CMake at it, or `find_package(OpenSSL)` will pick up the
system LibreSSL headers and fail:

**macOS**

```bash
brew install openssl@3
cmake -S . -B build-openssl -DCMAKE_BUILD_TYPE=Release -DRNGSDK_USE_OPENSSL=ON \
      -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

**Linux**

```bash
sudo apt install -y libssl-dev
cmake -S . -B build-openssl -DCMAKE_BUILD_TYPE=Release -DRNGSDK_USE_OPENSSL=ON
```

Then, on both:

```bash
cmake --build build-openssl -j"$JOBS"
./build-openssl/rng_tests
```

Use `build-openssl/rng_stream` for every run if you built it — it provides all
six sources; the plain `build/` one provides five.

## 2. Determinism handshake — do this before anything else

Your build must produce byte-identical output to the development build. If it
does not, every log you send back is unattributable, and we would rather find
that out now than after two days of runs.

```bash
# Point RNG at whichever build you made. The bundled build has five sources;
# the OpenSSL build adds `ctr`.
RNG=./build-openssl/rng_stream        # or ./build/rng_stream
SOURCES="xoshiro pcg64 hmac pf randu" # add ctr only if you built with OpenSSL

for s in $SOURCES; do
  printf '%-8s ' "$s"
  $RNG --source "$s" --seed 1 --bytes 32 | xxd -p -c 32
done
```

Compare against `docs/statistical_results/fingerprints.txt`. **Every line must
match.** If any line differs, stop and report it — that is a real portability
bug in the SDK and is more valuable than the battery runs.

## 3. Install the batteries

`curl` is preinstalled on macOS; `wget` is not. The commands below use `curl`,
which is present on both platforms.

**Dieharder** — source build on macOS; distro package on Linux.

**Linux** — the distribution package is fine and is the preferred provenance:

```bash
sudo apt install -y dieharder
```

**macOS** — there is no package. `brew install dieharder` fails with "No
available formula". This is not a mistake in this runbook and not something to
work around by searching for a tap: the formula was *disabled* on 2022-01-17
because the upstream tarball host (`webhome.phy.duke.edu`) serves an incomplete
SSL certificate chain, and Homebrew removes disabled formulae after a year.
MacPorts has no `dieharder` port either — `diehard` is Marsaglia's original,
a different and much smaller tool; do not substitute it.

Build from source, and **use the git repository, not the 3.31.1 tarball**:

```bash
brew install gsl autoconf automake libtool     # GSL is the only hard dependency

git clone https://github.com/eddelbuettel/dieharder.git ~/src/dieharder
cd ~/src/dieharder
git rev-parse HEAD                              # RECORD THIS — it is the version
autoreconf -i

./configure --prefix="$HOME/opt/dieharder" \
    CPPFLAGS="-I$(brew --prefix gsl)/include" \
    LDFLAGS="-L$(brew --prefix gsl)/lib" \
    CFLAGS="-O2 -Wno-implicit-function-declaration"

make -j"$JOBS" && make install
export PATH="$HOME/opt/dieharder/bin:$PATH"     # add to ~/.zshrc to persist
dieharder -V
```

Why the git repo specifically: dieharder 3.31.1 (2011, the last tarball
release) does not link on ARM64 —

```
Undefined symbols for architecture arm64:
  "_insert",    referenced from: _dab_filltree  in libdieharder.a(...)
  "_insertBit", referenced from: _dab_filltree2 in libdieharder.a(...)
```

— because `dab_filltree.c` and `dab_filltree2.c` define those helpers as bare
`inline`. Under C99/C11 semantics an `inline` definition with no matching
`extern` declaration emits **no external symbol**; GCC's older gnu89-inline
default, which Debian built with, masked the bug for a decade. It was fixed
upstream by adding `static` to the four declarations (eddelbuettel/dieharder
PR #1, merged 2022-08-07), so **master builds clean and needs no patch from
you**. If you see that linker error, you are building the tarball, not the
clone.

`--prefix="$HOME/opt/dieharder"` keeps this out of `/usr/local` and away from
Homebrew's tree. If `dieharder` starts but cannot find `libdieharder`, add
`export DYLD_LIBRARY_PATH="$HOME/opt/dieharder/lib:$DYLD_LIBRARY_PATH"`.

Record `git rev-parse HEAD` and the `dieharder -V` banner in the log. Because
this is a git build rather than a released version, the commit hash *is* the
version number and the results are not reproducible without it.

*Fallback, only if the source build fails:* run Debian's packaged dieharder in
a container and pipe into it — provenance is actually better this way, since
the binary is then distribution-built and wholly unmodified by us.

```bash
docker build -t dh - <<'EOF'
FROM debian:stable
RUN apt-get update && apt-get install -y --no-install-recommends dieharder \
    && rm -rf /var/lib/apt/lists/*
EOF
$RNG --source xoshiro | docker run --rm -i dh dieharder -a -g 200
```

Expect lower throughput through the container's stdin on macOS (the Linux VM
adds a copy), so prefer the native build for the deep runs.

**TestU01** — source build, identical on both:

```bash
curl -L -O http://simul.iro.umontreal.ca/testu01/TestU01.zip
unzip TestU01.zip && cd TestU01-*/
./configure --prefix="$HOME/testu01"
make -j"$JOBS" && make install
cd ..
# headers/libs then live in ~/testu01/{include,lib}
```

**PractRand** — source drop. Note the `/download` suffix: without it
SourceForge serves an HTML landing page and `unzip` fails on a file that is
not a zip.

```bash
curl -L -o PractRand.zip \
  https://sourceforge.net/projects/pracrand/files/PractRand-pre0.95.zip/download
unzip PractRand.zip -d practrand && cd practrand

# PractRand pre0.95 predates stricter header hygiene: several files use
# uint8_t etc. without including <cstdint>. Hard error on GCC >= 11 and on
# recent Apple clang. This prepend works on both BSD and GNU sed:
printf '#include <cstdint>\n' | cat - include/PractRand/config.h > /tmp/prcfg \
  && mv /tmp/prcfg include/PractRand/config.h

g++ -c src/*.cpp src/RNGs/*.cpp src/RNGs/other/*.cpp -O3 -Iinclude -pthread
ar rcs libPractRand.a *.o
g++ -O3 -Iinclude tools/RNG_test.cpp libPractRand.a -o RNG_test -pthread
cd ..
```

**NIST STS** — GCC >= 10 and clang >= 11 both default to `-fno-common`, and
STS has tentative definitions in its headers, so it will not link without
`-fcommon`. Apple clang additionally treats implicit function declarations as
errors, which this 2010 code triggers:

```bash
curl -L -O https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip
unzip sts-2_1_2.zip && cd sts-2.1.2/sts-2.1.2

# macOS
make CC=clang CFLAGS="-fcommon -O2 -Wno-implicit-function-declaration"
# Linux
make CFLAGS="-fcommon -O2"
```

Known snags:
* PractRand and STS are 10–15 year old codebases. The failures called out
  above (`<cstdint>`, `-fcommon`, implicit declarations) are hard errors on
  any current toolchain, not warnings. If you hit a *different* one, report it
  rather than patching around it silently — a modified battery is a battery
  whose results need a caveat.
* On macOS, Homebrew's binaries are under `/opt/homebrew` (Apple Silicon) or
  `/usr/local` (Intel); if a brew-installed tool is not found, run
  `eval "$(brew shellenv)"`. Dieharder is *not* one of them — it installs to
  `$HOME/opt/dieharder/bin` per §3 and needs that on `PATH` separately.
* **Validate every battery build before trusting a pass from it** — §3.5 is
  the gate, and no run in §5 starts until all four clear it.
* PractRand needs `-pthread`; it warns loudly on modern compilers. Warnings
  are fine, errors are not.
* NIST STS writes results into its own `experiments/` tree and must be run
  from its own directory.
* TestU01 installs to a prefix; pass `-I$HOME/testu01/include
  -L$HOME/testu01/lib` when compiling the driver in §5.

## 3.5 Gate — all four batteries installed and proven, before any real run

Do not start a single run in §5 until **all four** batteries are built and
each has passed the smoke test below. The reason is practical: the deep runs
take days, they are the expensive thing here, and discovering on day three
that a battery was misbuilt means the runs it produced are unattributable.
Installing all four first also surfaces every toolchain problem in one sitting
rather than three separate ones.

The smoke test is the same idea in each case: feed **RANDU** — our deliberately
broken generator — at the cheapest setting the battery supports, and confirm
the battery notices. A battery that cannot detect RANDU cannot be trusted to
detect anything, and this costs minutes rather than days.

```bash
RNG=./build-openssl/rng_stream        # or ./build/rng_stream
mkdir -p /tmp/smoke
```

| Battery | Smoke command | Must show |
|---|---|---|
| Dieharder | `$RNG --source randu \| dieharder -d 0 -g 200` | `FAILED` |
| PractRand | `$RNG --source randu \| ./practrand/RNG_test stdin64 -tlmax 256M` | `FAIL` / `suspicious`, and it should stop early |
| TestU01 | `$RNG --source randu \| ./tu01_stdin s` | a long list of failed tests in the summary |
| NIST STS | 2 MB file, 16 bitstreams (below) | most tests non-uniform / low proportion |

Dieharder's `-d 0` runs `diehard_birthdays` alone, which is the test RANDU's
lattice structure dies on fastest. If `-d 0` is rejected by your build, run
`dieharder -l` and use the number listed for `diehard_birthdays`.

NIST STS smoke run — this also proves you can answer the prompts correctly,
which is the part most likely to go wrong:

```bash
$RNG --source randu --bytes 2M > /tmp/smoke/randu.bin   # 2,097,152 bytes = 16 bitstreams
cd sts-2.1.2/sts-2.1.2 && ./assess 1000000
```
Answer `0`, `/tmp/smoke/randu.bin`, `1`, `0`, `16`, **`1` (binary)**. If you
answer `0` at the last prompt you are testing ASCII text, not your file, and
the report is meaningless — see §5.

**Stop here and report the four smoke results before continuing.** Once all
four are green, everything in §5 can be launched together and left to run.

## 4. The run matrix

Six sources. `xoshiro`, `pcg64`, `pf`, `randu` get **deep** runs; `hmac` and
`ctr` get **shallow** runs (they are already validated byte-for-byte against
NIST CAVP vectors; the plausible defect there is a gross buffering fault,
which dies in the first megabyte).

`randu` is the **negative control**. It is a deliberately broken generator and
it MUST fail. If RANDU passes a battery, that battery is misconfigured and its
other results are void — report it rather than filing it as a pass.

| Battery | deep sources | shallow sources |
|---|---|---|
| NIST STS | full, 125 MB | full, 125 MB |
| Dieharder | `-a` (all tests) | `-a` (all tests) |
| TestU01 | SmallCrush, Crush, BigCrush | SmallCrush |
| PractRand | to 256 GB or first failure | to 8 GB |

Save every log — including failures, especially failures — as
`docs/statistical_results/<battery>_<source>.log`.

**One extra `pf` run, cheap and worth it.** At the default 32 bytes per nonce
every emitted block has cursor 0, so the cursor path is never exercised by a
battery. Production code does use it: `pf::Generator::NextFloats(..., n)`
draws 4n bytes from a *single* nonce, so a multi-card draw crosses blocks. Add
one PractRand run to 8 GB with a wide per-nonce budget:

```bash
$RNG --source pf --pf-bytes-per-nonce 4096 | ./practrand/RNG_test stdin64 -tlmax 8G \
  2>&1 | tee "$OUT/practrand_pf_cursor.log"
```

## 5. Commands

Set once:

```bash
RNG=./build-openssl/rng_stream       # or ./build/rng_stream (no `ctr` source)
OUT=docs/statistical_results
mkdir -p "$OUT"
DEEP="xoshiro pcg64 pf randu"
SHALLOW="hmac ctr"                   # drop ctr on a bundled-only build
```

Commands below are written for one source; run each over the whole tier. For
example:

```bash
for s in $DEEP; do
  $RNG --source "$s" | ./practrand/RNG_test stdin64 -tlmax 256G 2>&1 | tee "$OUT/practrand_$s.log"
done
```

**PractRand** (streams; no disk needed):

```bash
$RNG --source xoshiro | ./practrand/RNG_test stdin64 -tlmax 256G 2>&1 | tee "$OUT/practrand_xoshiro.log"
$RNG --source hmac    | ./practrand/RNG_test stdin64 -tlmax 8G   2>&1 | tee "$OUT/practrand_hmac.log"
```

`rng_stream` runs until the pipe closes, so PractRand controls when it stops.

**Dieharder** (`-g 200` = raw binary on stdin):

```bash
$RNG --source xoshiro | dieharder -a -g 200 2>&1 | tee "$OUT/dieharder_xoshiro.log"
```

Dieharder rewinds a file but not a pipe; if it reports rewind warnings, dump
to a file first (`--bytes 8G`) and use `-g 201 -f file.bin`.

**NIST STS** (needs a real file — it cannot read a pipe):

```bash
$RNG --source xoshiro --bytes 125M > /tmp/xoshiro.bin   # 131,072,000 bytes
cd sts-2.1.2/sts-2.1.2
./assess 1000000
```

`assess` is interactive. Answer, in order:

| Prompt | Answer |
|---|---|
| Generator selection | `0` (Input File) |
| User Prescribed Input File | `/tmp/xoshiro.bin` |
| Statistical Tests | `1` (apply all tests) |
| Parameter Adjustments | `0` (continue with defaults) |
| How many bitstreams? | `1048` |
| Input File Format | **`1` (binary)** |

Two of those are easy to get wrong and neither errors out:

* **Input File Format must be `1` (binary).** The default, `0`, makes STS read
  the file as ASCII `'0'`/`'1'` characters. It will happily produce a full
  report from garbage. This is the single most likely way to file a
  meaningless pass.
* **Bitstream count.** `--bytes 125M` is 125 × 1024² = 131,072,000 bytes =
  1,048,576,000 bits = **1048** complete bitstreams of 10^6 bits (the
  remainder is ignored). Entering a smaller number silently tests only that
  fraction of the file — e.g. `100` tests ~12.5 MB while the matrix claims a
  125 MB run.

Copy `experiments/AlgorithmTesting/finalAnalysisReport.txt` to
`$OUT/nist_<source>.log`.

**TestU01** needs a small C driver — build it once:

```c
/* tu01_stdin.c — feeds TestU01 from rng_stream on stdin */
#include <stdio.h>
#include <stdlib.h>   /* exit(); GCC >= 14 defaults to -std=gnu23, where an
                         implicit declaration is an error, not a warning */
#include "unif01.h"
#include "bbattery.h"
static unsigned int NextWord(void *p, void *s) {
    (void)p; (void)s;
    unsigned int x;
    if (fread(&x, sizeof x, 1, stdin) != 1) { fprintf(stderr, "stdin exhausted\n"); exit(1); }
    return x;
}
int main(int argc, char **argv) {
    unif01_Gen *gen = unif01_CreateExternGenBits((char *)"rng_stream", NextWord);
    if (argc > 1 && argv[1][0] == 'b') bbattery_BigCrush(gen);
    else if (argc > 1 && argv[1][0] == 'c') bbattery_Crush(gen);
    else bbattery_SmallCrush(gen);
    unif01_DeleteExternGenBits(gen);
    return 0;
}
```

```bash
gcc -O2 -I"$HOME/testu01/include" tu01_stdin.c -o tu01_stdin \
    -L"$HOME/testu01/lib" -ltestu01 -lprobdist -lmylib -lm

$RNG --source xoshiro | ./tu01_stdin s 2>&1 | tee "$OUT/testu01_small_xoshiro.log"
$RNG --source xoshiro | ./tu01_stdin c 2>&1 | tee "$OUT/testu01_crush_xoshiro.log"
$RNG --source xoshiro | ./tu01_stdin b 2>&1 | tee "$OUT/testu01_big_xoshiro.log"
```

On macOS, `gcc` is a shim for clang and works here unchanged.

Run the long ones under `nohup`/`tmux` (`brew install tmux`) — BigCrush is
hours, PractRand at
256 GB is longer.

## 6. Reading the results

**A handful of marginal p-values is expected, not alarming.** Under the null
hypothesis p-values are uniform on [0,1], so across BigCrush's ~160 tests you
should see roughly one or two below 0.01 by chance alone. A report claiming
"160/160, zero anomalies" is a report to distrust.

The convention we use:

* p < 1e-10 — a **failure**. Investigate; this is not luck.
* 1e-10 ≤ p < 0.001 — **suspect**. Re-run that source with a different
  `--seed`. If it moves, it was noise; if it persists at the same test, it is
  real.
* otherwise — pass.

Note in the log *which* test produced any suspect value and what the re-run
seed and outcome were. That adjudication record is what makes the final
matrix falsifiable, and it is the part reviewers actually read.

## 7. Returning results

Commit the logs under `docs/statistical_results/` (or send the directory) plus
a short note per battery: tool version, exact command, machine (CPU, RAM, OS),
wall-clock time. `dieharder -V`, PractRand's banner, and the STS report header
all print versions. For dieharder on macOS also give the **git commit hash**
from §3 — it is a source build, so `-V` alone does not identify what ran.

On macOS the machine line is:

```bash
sysctl -n machdep.cpu.brand_string; sysctl -n hw.memsize; sw_vers
```

Machine details matter for the report's methodology section and feed open
item #9 (platform matrix), so please include them even though they feel
irrelevant to a pass/fail. If this is an Apple Silicon Mac, note the chip
(M1/M2/M3/M4) explicitly — it is the first non-x86 data point in the project.
