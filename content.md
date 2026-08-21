# Attack surface: Telegram Desktop — Instant View / markdown math rendering (bundled MicroTeX, github.com/desktop-app/MicroTeX)
# Severity: 7.5 (Finding 1, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H); 6.5 (Finding 2, CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## Description:
Telegram Desktop renders LaTeX math in Instant View / markdown content using the bundled MicroTeX engine (submodule desktop-app/MicroTeX). This report covers two independent memory-safety vulnerabilities in that engine. They share one attack surface and one delivery vector but have distinct root causes, sinks, severities, and fixes, and can be triaged independently. Both are present at MicroTeX commit 55b801c, matching Telegram Desktop 6.9–6.9.3.

- Finding 1 — `\kern` out-of-bounds indirect call (CVSS 7.5). A `\kern` with no length argument produces a negative index into a global table of `std::function` objects; the engine invokes the out-of-bounds entry, loading the instruction pointer from adjacent memory. A control-flow-hijack primitive.
- Finding 2 — `\multirow` heap buffer overflow (CVSS 6.5). A `\multirow` row span exceeding the matrix's real row count reads a garbage pointer past the row arrays (8-byte OOB read, dereferenced) and performs a bounded OOB write past two `new float[rows]` allocations.

### Shared reachability and delivery
`LaTeX::parse` runs during ordinary message layout, not only when a standalone article is deliberately opened:

    HistoryView message layout
      -> Iv::Markdown::TryPrepareNativeInstantView -> MeasureNativeIvPreparedFormulas
        -> MathRenderer::measureFormula -> MeasureWithMicrotex -> ParseFormula
          -> tex::LaTeX::parse   (iv/markdown/iv_markdown_microtex.cpp:280)
            -> SpaceAtom::createBox  -> SpaceAtom::getFactor          (Finding 1)
            -> MatrixAtom::createBox -> MatrixAtom::recalculateLine   (Finding 2)

A bot can emit a message whose native Instant-View math content (rich_message) carries the trigger. Forwarding that message to any user, group, supergroup, or channel carries the content with it, so every recipient's client reaches the vulnerable path when the chat is laid out for display. Compose-box `$$...$$` text does not reach this path; a forwarded bot message does. Math formulas are not validated server-side.

---

### Finding 1 — `\kern` out-of-bounds indirect call
1. `macro(kern)` (src/core/macro_impl.cpp:12) calls `TeXParser::getLength()`, which at end-of-input returns `{UnitType::none, -1.f}` (parser.cpp:694). The resulting `SpaceAtom` carries `_wUnit = none`.
2. `UnitType` is backed by `i8` and defines `none = -1` (enums.h:99-124); the 14 real units occupy indices 0..13.
3. `SpaceAtom::createBox` (atom_space.cpp:19) evaluates `_width * getFactor(_wUnit, env)`:

       inline static float getFactor(UnitType unit, const Environment& env) {
         return _unitConversions[static_cast<i8>(unit)](env);
       }

`_unitConversions` (unit_conversion.cpp:31) is a fixed global array of exactly 14 `std::function<float(const Environment&)>`, with no bounds check. For `none`, `static_cast<i8>(none) == -1`, so `_unitConversions[-1]` reinterprets the 32-byte global immediately before the array as a `std::function` and calls `operator()` on it. libstdc++'s `operator()` performs an indirect call through the `_M_invoker` slot (offset +0x18): the engine reads a function pointer out of a foreign global and jumps to it. AddressSanitizer traps the read inside `_M_empty()` before the call, so ASan observes only an out-of-bounds read; in an ordinary build the control transfer executes and `rip` is loaded from out-of-bounds memory. The sibling sink `getSize` (atom_space.h:48-49) has the identical unguarded pattern; a fix must cover both.

### Finding 2 — `\multirow` heap buffer overflow
`MatrixAtom::recalculateLine` (src/atom/atom_matrix.cpp) walks a `\multirow` span with no bound against the real row count:

    const int mr = m->_i + m->_n;
    for (int j = m->_i; j < mr; j++) {
      if (boxarr[j][0]->_type != AtomType::hline) {
        height[j] += ex;
        depth[j]  += ex;
      }
    }

The sibling counting loop a few lines above already guards this (`j < r + n && j < rows`); this loop does not. A `\multirow{9}` in a 1-row array yields an 8-byte heap OOB read of `boxarr[j]` (a garbage `shared_ptr<Box>*`, dereferenced via `->_type`) and a bounded heap OOB write (`height[j] += ex; depth[j] += ex`) past two `new float[rows]` allocations. `boxarr`, `height`, and `depth` are raw `new[]` arrays, so `_GLIBCXX_ASSERTIONS` hardening does not apply. The existing span cap (`kMaxArrayRowSpan = 1000`, macro_impl.h) bounds `|n|` but is never tied to the row count, so it does not prevent the overrun.

## Steps to reproduce:

### Finding 1 (`\kern`)
[1] Deterministic (proven). Build MicroTeX at 55b801c and parse the 5-byte payload `\kern` through `tex::LaTeX::parse()`:
  - AddressSanitizer: global-buffer-overflow, READ of size 8, in `SpaceAtom::getFactor` (atom_space.h:45), 16 bytes before `_unitConversions` / 8 bytes after `tex::PI` — pinning `_unitConversions[-1]` (finding1_kern/asan_trace.txt). ASan traps the read before the indirect call and so cannot show the transfer.
  - Release build under gdb: SIGSEGV, 20/20 runs, `#0 rip = 0x0`, reached through `std::function::operator()` on the object at `<tex::PI>` occupying `_unitConversions[-1]`, whose `_M_invoker` bytes are `0x0` in that binary — `rip` is loaded from data and jumped to. Harness: finding1_kern/poc/pwn. Detail: finding1_kern/gdb_evidence.md.

[2] Live client (partially confirmed). Forward a bot message whose Instant-View math content contains `\kern` to a target on Telegram Desktop 6.9–6.9.3.

[3] The recipient's client crashes in the `SpaceAtom` path during layout. Four crash dumps (2026-07-03) carry the control-flow signature: `rip` above the telegram-desktop module range (0x555555554000–0x55555d561000), in the heap, with `rip == fault address`; `rip` varies per run (…70455100 / …73213180 / …6ee671a0 / …74ca9e00) while `rdi` (= `&_M_functor` = 0x5555625ff060, the fixed global at `_unitConversions[-1]`) and `rcx/r8/r9/r10/r14` stay constant — the fingerprint of a deterministic `_M_invoker(&globalFunctor, env)` reading its target from memory, which random corruption does not reproduce. Two were reproduced live on demand (08:19:06, 08:20:18). Of 100 dumps on disk, only these 4 carry this signature; the rest crash with `rip` in valid code and are not attributed to `\kern`. Excerpts: finding1_kern/gdb_evidence.md.

### Finding 2 (`\multirow`)
[1] Deterministic (proven). Build MicroTeX at 55b801c and parse:

      \begin{array}{c}\multirow{9}{*}{x}\end{array}

  AddressSanitizer: heap-buffer-overflow, READ of size 8, in `MatrixAtom::recalculateLine` (atom_matrix.cpp:315), in the region allocated at atom_matrix.cpp:441 (`new sptr<Box>*[rows]`, 1-row array). Reproduces identically across runs, and with `\multirow{-9}`, `\multirow{99}`, and inside `\begin{matrix}`. Trace: finding2_multirow/asan_trace.txt.

[2] Live client. Forward a bot message whose Instant-View math content contains the trigger to a target on Telegram Desktop 6.9–6.9.3.

[3] The chat being displayed crashes in `MatrixAtom::recalculateLine` during layout, on every subsequent open, until the message is removed/edited server-side or the client is patched. Reproduced on the official 6.9.3 Linux x86_64 release build (crash IDs below; screenshots in finding2_multirow/gdb/).

Open question (both findings, shared reachability): whether the crash fires only when the recipient opens the specific chat/article (UI:R), or when the message is merely received and auto-rendered during layout/preview (UI:N). Finding 1 is scored at UI:N (7.5); Finding 2 conservatively at UI:R (6.5). We will confirm and align both scores if it changes.

## Impact:
Two remotely reachable, unauthenticated memory-safety defects in Telegram Desktop's bundled Instant-View math renderer, each triggered by a forwarded bot message and each hitting every viewer during ordinary chat rendering.

Finding 1 (`\kern`) — CVSS 7.5, AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H. Demonstrated impact: a deterministic, near-zero-click remote crash, confirmed in isolation (ASan + release-build gdb) and against the live client (four crash dumps, two reproduced on demand). Unlike a plain denial of service, it transfers control: the instruction pointer becomes a value read from `_unitConversions[-1]._M_invoker`, landing in the heap on the shipping client — a control-flow-hijack primitive (CWE-129 → CWE-125 → CWE-843). Code execution is not demonstrated: the jump currently lands on incidental heap bytes that decode to a faulting instruction. Weaponization would require controlling the `_M_invoker` slot of the fixed global at `_unitConversions[-1]`, or heap-grooming the target region from the same Instant-View content — neither attempted, both non-trivial against the deployed ASLR, and there is no accompanying information leak (the out-of-bounds value is consumed by the call, never returned). If weaponized, the ceiling rises toward CVSS 8.8. We report the demonstrated 7.5 and recommend exploit-development triage before any downgrade to plain DoS.

Finding 2 (`\multirow`) — CVSS 6.5, AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H. A heap out-of-bounds read plus a bounded heap out-of-bounds write (CWE-125 + CWE-787), confirmed in isolation and reproduced on the official 6.9.3 build. This is memory corruption, not a logic crash — `height[j]` and `depth[j]` are written out of bounds — but code execution is not claimed: the write is a geometry-derived `float +=` onto an unknown existing value (no value control), the gating out-of-bounds read never leaves the function (no information leak), and the pointer dereference on the read side usually faults before the write lands. It never transfers control (`rip` stays in valid code), which is why it scores below Finding 1.

Blast radius (both): the trigger travels with the forwarded message, so one forward into a group, supergroup, or channel puts the crash in front of every member who subsequently renders that chat — per-viewer, not a one-time hit — and can crash-loop a victim on every open until the message is removed or edited server-side, or the client is patched.

## Additional details:

Finding 1 — sink and fix. atom_space.h `SpaceAtom::getFactor` (line 45) and `getSize` (line 49); trigger atom built at macro_impl.cpp:12; `none` originates at parser.cpp:694; array at unit_conversion.cpp:31 (14 entries). Proposed fix — bounds-check both sinks:

    inline static float getFactor(UnitType unit, const Environment& env) {
      const auto i = static_cast<i8>(unit);
      if (i < 0 || i >= _unitConversionsCount) return 0.f; // none / OOB -> no space
      return _unitConversions[i](env);
    }
    inline static float getSize(UnitType unit, float size, const Environment& env) {
      const auto i = static_cast<i8>(unit);
      if (i < 0 || i >= _unitConversionsCount) return 0.f;
      return _unitConversions[i](env) * size;
    }

The bound must be the length of `_unitConversions` (14), not `_unitsCount` (16, the separate `_units[]` alias table); add an explicit `_unitConversionsCount = sizeof(_unitConversions)/sizeof(_unitConversions[0])`. Returning `0.f` matches the existing unknown-unit fallback (atom_space.cpp:13). Defense in depth: reject `UnitType::none` inside `macro(kern)`. Diff: finding1_kern/fix.md. Payload: `\kern` (finding1_kern/payload.txt).

Finding 2 — sink and fix. atom_matrix.cpp `MatrixAtom::recalculateLine`, the `h < bh` branch (working-tree line ~313-320 at 55b801c). Proposed fix — clamp the loop to the real row count at both ends, mirroring the sibling loop's existing guard:

    const int mr = std::min(m->_i + m->_n, rows);
    for (int j = std::max(m->_i, 0); j < mr; j++) { ... }

(`min()` fixes the observed overrun; `max()` guards the lower bound.) Verified: rebuilding against the patched source and re-running all PoCs exits cleanly under AddressSanitizer. Diff: finding2_multirow/fix.md. Payloads (all reproduce under ASan at 55b801c):

    \begin{array}{c}\multirow{9}{*}{x}\end{array}
    \begin{array}{c}\multirow{-9}{*}{x}\\a\end{array}
    \begin{array}{c}\multirow{99}{*}{x}\end{array}
    \begin{array}{c}\multirow{5}{*}{x}\end{array} \begin{matrix}\multirow{20}{*}{x}\end{matrix}

Provenance and versions. Both defects originate upstream in MicroTeX and are inherited by desktop-app/MicroTeX. The `\multirow` loop dates to upstream commit 44d9d1f (2021); the unguarded unit index is likewise longstanding. Both are reachable since the Instant-View math renderer was added (6.8.x beta line; stable channel since 6.9) through 6.9.3. Confirmed against 6.9–6.9.3 (commit 55b801c); the first affected beta is not separately pinned.

Official-build crash-report IDs (Finding 2, 6.9.3 Linux x86_64):

    08682c91-c5cc-4d26-51110f98-722b8617
    ff1d7b35-4db4-46c0-7ddc9085-8ba40a37
    9ba7274e-c2de-48e5-75dcf49a-a4b80b97
    03a29b41-17c7-4a6d-26c1e0bc-a1cf4495

Attachments.
- finding1_kern/ — ASan trace, minimal standalone harness (poc/, parses `\kern` through `tex::LaTeX::parse` with no Qt/UI dependency), gdb_evidence.md (release-build backtrace plus the four crash-dump register/stackwalk excerpts, two live-reproduced), fix diff, payload.
- finding2_multirow/ — ASan trace (two independent runs), fix diff, payload, gdb/ (crash screenshots from the official 6.9.3 build).

Contact: Telegram @gearonixx · egor.uzhanin@gmail.com