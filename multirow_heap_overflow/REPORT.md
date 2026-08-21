# Attack surface: Telegram Desktop — Instant View / markdown math rendering (bundled MicroTeX, github.com/desktop-app/MicroTeX submodule)
# Severity: 6.5 (CVSS v3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H) see note on blast radius under Impact

## Description:
Telegram Desktop renders LaTeX math in Instant View / markdown message content using the bundled MicroTeX engine (submodule github.com/desktop-app/MicroTeX, consumed by telegramdesktop/tdesktop). MatrixAtom::recalculateLine (Telegram/ThirdParty/MicroTeX/src/atom/atom_matrix.cpp) walks a \multirow row span with no bound against the array/matrix's real row count:

    const int mr = m->_i + m->_n;
    for (int j = m->_i; j < mr; j++) {
      if (boxarr[j][0]->_type != AtomType::hline) {
        height[j] += ex;
        depth[j]  += ex;
      }
    }

There is no `j < rows` guard, unlike the sibling counting loop a few lines above in the same function, which already has one (`for (int j = r; j < r + n && j < rows; j++)`). A \multirow whose span reaches past the rows that actually follow it (e.g. \multirow{9} inside a single-row array) causes:

- an 8-byte heap out-of-bounds READ of boxarr[j] (a garbage shared_ptr<Box>*), which is then dereferenced twice more (->_type comparison);
- a bounded heap out-of-bounds WRITE (height[j] += ex; depth[j] += ex) past two `new float[rows]` heap allocations.

boxarr, height and depth are raw new[]-allocated arrays (not std::vector), so none of libstdc++'s _GLIBCXX_ASSERTIONS bounds hardening applies — in a release build the overrun simply executes. The existing magnitude cap on the span (kMaxArrayRowSpan = 1000, src/core/macro_impl.h) bounds |n| but never ties it to the actual row count, so it does not prevent this overrun (\multirow{9} in a 1-row array is well within the cap and still overruns by 8 rows).

Reachability: MicroTeX's LaTeX::parse is invoked from Telegram's Instant View markdown math path (Telegram/SourceFiles/iv/markdown/iv_markdown_microtex.cpp), which is itself driven from ordinary message layout — HistoryView::Element::validateText -> Iv::Markdown::TryPrepareNativeInstantView -> MeasureNativeIvPreparedFormulas -> MathRenderer::measureFormula -> MeasureWithMicrotex -> ParseFormula -> tex::LaTeX::parse -> MatrixAtom::createBox -> MatrixAtom::recalculateLine. This code path runs whenever a message carrying native Instant-View math content is laid out for display in the chat view, i.e. it is exercised during normal message rendering rather than requiring the user to deliberately open a standalone article.

Delivery vector: a bot can produce a message whose native Instant-View math content (rich_message) contains the malicious `\multirow` formula. That message, once forwarded to any user, group, supergroup, or channel, carries the same rich_message content with it — so any recipient's Telegram Desktop client hits the vulnerable code path as soon as that chat is displayed. Ordinary compose-box text ("$$...$$") does not trigger this path; forwarding a bot-generated message is what actually reaches the renderer.

## Steps to reproduce:
[1] Standalone / deterministic (fully proven): build MicroTeX at the commit pinned by Telegram Desktop 6.9–6.9.3 (submodule desktop-app/MicroTeX, working tree commit 55b801c) and call tex::LaTeX::parse() directly on the string:

      \begin{array}{c}\multirow{9}{*}{x}\end{array}

    This deterministically crashes under AddressSanitizer: heap-buffer-overflow, READ of size 8, in tex::MatrixAtom::recalculateLine at atom_matrix.cpp:315, in the 8-byte region allocated at atom_matrix.cpp:441 (new sptr<Box>*[rows] for a 1-row array). Reproduced identically across independent runs (different ASLR bases/PIDs, identical fault site, allocation site, call chain and shadow-memory pattern). Also reproduces with \multirow{-9} (negative span), \multirow{99}, and inside \begin{matrix}...\end{matrix} as well as \begin{array}...\end{array} — not environment-specific. ASan traces attached.

[2] Live/in-product (source-traced, not yet independently confirmed against telemetry on our end): create a bot message whose native Instant-View math content contains the trigger formula (e.g. \begin{array}{c}\multirow{9}{*}{x}\end{array}), then forward that message to a target user, group, supergroup, or channel using Telegram Desktop.

[3] Per the call chain in the Reachability paragraph above, the target chat being displayed on the recipient's Telegram Desktop client (6.9–6.9.3) should cause the client to parse the formula during message layout and crash in MatrixAtom::recalculateLine, on every subsequent open of that chat, until the message is removed/edited server-side or the client is patched. We want to flag explicitly that we are basing this step on the traced source-level call chain, not on a confirmed live crash captured on our own machine — we do not want to overstate what has actually been observed versus what follows from reading the code.

One detail we're still pinning down: whether the crash fires only once the recipient opens that specific chat (near-zero-click, UI:R — what this report is scored against), or also from the chat simply being visible in the chat list without being opened (true zero-click, UI:N). We'll confirm which applies and follow up if it changes the score.

## Impact:
A confirmed heap out-of-bounds read plus a bounded heap out-of-bounds write (CWE-125 + CWE-787) in MicroTeX's \multirow layout code, reachable through Telegram Desktop's bundled Instant View math renderer via a forwarded bot-generated message. The deterministic, reliable crash (denial of service) is confirmed in isolation against the exact MicroTeX commit Telegram Desktop 6.9–6.9.3 ships (standalone ASan harness, two independent runs, identical fault/allocation sites — see attached traces); the same outcome against the live client via the forward-based delivery path follows directly from the traced source-level call chain but has not yet been separately confirmed against this vulnerability specifically (as opposed to other, unrelated crashes we observed on this machine) via captured crash telemetry, and we want to be upfront about that distinction rather than overstate it. The defect is memory corruption, not just a logic crash: height[j]/depth[j] are written out of bounds. Blast radius: because the trigger travels with the forwarded message itself, a single forward into a group, supergroup, or channel should put the same crash in front of every member who subsequently views that chat — the vulnerability is per-viewer (each client independently parses the same message), not a one-time hit, so practical exposure scales with the size of the chat it's forwarded into even though the CVSS base score is computed per victim. We are not claiming remote code execution — the write is a geometry-derived float += onto an unknown existing value (no value control), the preceding OOB read that gates it never leaves the function (no info leak), and the triple-pointer dereference on the read side is likely to fault before the write is reached in most real heap layouts, since the garbage pointer at that offset is rarely both non-null and readable. We consider this a genuine heap-write primitive worth triaging as memory-safety rather than a plain DoS, without an accompanying code-execution demonstration.

## Additional details:
- Exact file/function: Telegram/ThirdParty/MicroTeX/src/atom/atom_matrix.cpp, MatrixAtom::recalculateLine, the "h < bh" branch (working-tree line ~313-320 at submodule commit 55b801c, matching what ships in Telegram Desktop 6.9-6.9.3).
- Suggested fix: clamp the loop range to the real row count at both ends, mirroring the guard the sibling counting loop already has a few lines above:

    const int mr = std::min(m->_i + m->_n, rows);
    for (int j = std::max(m->_i, 0); j < mr; j++) { ... }

  (min() is the load-bearing fix for the observed overrun; max() is a defensive lower-bound guard.) We verified this clamp eliminates the overflow: rebuilding against the patched source and re-running all PoCs exits cleanly under AddressSanitizer.
- The unguarded loop originates upstream in MicroTeX (commit 44d9d1f, 2021), inherited by Telegram's fork desktop-app/MicroTeX, and is present in every Telegram Desktop build that ships MicroTeX (introduced 6.8.3 beta; in the stable channel since 6.9), through the current 6.9.3.
- PoC inputs (all reproduce 6/6 under ASan against the pinned MicroTeX commit):
    \begin{array}{c}\multirow{9}{*}{x}\end{array}
    \begin{array}{c}\multirow{-9}{*}{x}\\a\end{array}
    \begin{array}{c}\multirow{99}{*}{x}\end{array}
    \begin{array}{c}\multirow{9}{*}{\frac{a}{b}}\end{array}
    \begin{array}{c}\multirow{5}{*}{x}\end{array}\n\begin{matrix}\multirow{20}{*}{x}\end{matrix}
- Attached: full AddressSanitizer heap-buffer-overflow reports (two independent runs, identical fault/allocation sites and call chain), the minimal standalone reproduction harness (parses the payload directly through tex::LaTeX::parse with no Qt/Telegram UI dependency), and the source diff implementing the fix above.
- Telegram @gearonixx.
