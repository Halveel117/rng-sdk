// tools/write_csv.hpp — one CSV writer for every tool in this folder.
//
// WHY THIS EXISTS. Two properties have to hold at every CSV site, and both
// were previously re-derived by hand at five of them:
//
//  1. SEVENTEEN SIGNIFICANT FIGURES. 17 round-trips a double exactly. At the
//     stream default of 6, derived columns stop being re-derivable from the
//     columns they came from: pi_results.csv's `abs_err` was unrecomputable
//     in 50 of 56 rows, by up to 3.7% in the worst. The CSV is the auditable
//     artefact and must not be a lossy copy of what the tool computed.
//
//  2. AN EXPLICIT FLUSH BEFORE THE FAILURE CHECK. An ofstream destructor
//     flushes AFTER any `if (!f)` written below it, so a full disk leaves a
//     truncated file and the tool exits 0. That defect has regressed three
//     times in this repo (code review caught it in stream.cpp on 2026-08-18,
//     and the stability CSVs shipped with it again).
//
// Neither is hard. Both are easy to forget once, which is the whole argument
// for having exactly one copy.
//
// License: MIT.
#pragma once
#include <cstdio>
#include <fstream>
#include <ostream>
#include <string>

namespace rngtools {

// Writes `header`, then whatever `emit` streams, to `path`. Returns false and
// reports to stderr if any part of the write failed; the caller's exit code is
// its own business. `emit` is called with the open stream, already at 17
// significant figures.
template <class Emit>
bool WriteCsv(const std::string& path, const char* header, Emit&& emit) {
    std::ofstream f(path);
    f.precision(17);
    f << header;
    emit(f);
    f.flush();
    if (!f) {
        std::fprintf(stderr, "write failed: %s\n", path.c_str());
        return false;
    }
    return true;
}

} // namespace rngtools
