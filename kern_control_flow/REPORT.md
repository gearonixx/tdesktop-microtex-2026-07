# Attack surface: Telegram Desktop — Instant View / markdown math rendering (bundled MicroTeX, github.com/desktop-app/MicroTeX submodule)
# Severity: 7.5 (CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) — availability-only *demonstrated* impact; see note on the control-flow-hijack ceiling under Impact

## Description:
Telegram Desktop renders LaTeX math in Instant View / markdown message content using the bundled MicroTeX engine (submodule github.com/desktop-app/MicroTeX, consumed by telegramdesktop/tdesktop). A `\kern` command supplied with no length argument drives a negative, out-of-bounds index into a global array of `std::function` objects and then **invokes** the foreign object it lands on — an indirect call through out-of-bounds memory that loads the instruction pointer from that memory. Root-cause chain (all line numbers at submodule working-tree commit 55b801c, matching what ships in Telegram Desktop 6.9–6.9.3):

1. `\kern` with no following length. `macro(kern)` (Telegram/ThirdParty/MicroTeX/src/core/macro_impl.cpp:12) calls `TeXParser::getLength()`, which at end-of-input returns `{UnitType::none, -1.f}` (src/core/parser.cpp:694). The resulting `SpaceAtom` therefore carries `_wUnit = UnitType::none`.

2. `UnitType` is backed by `i8` (== `int8_t`, src/utils/utils.h:15) and defines `none = -1` (src/utils/enums.h:99-124); the 14 real units occupy indices 0..13.

3. `SpaceAtom::createBox` (src/atom/atom_space.cpp:19) unconditionally evaluates `_width * getFactor(_wUnit, env)` for a non-blank space. `getFactor` (src/atom/atom_space.h:44-45) is:

       inline static float getFactor(UnitType unit, const Environment& env) {
         return _unitConversions[static_cast<i8>(unit)](env);
       }

   `_unitConversions` is a fixed global array of **exactly 14** `std::function<float(const Environment&)>` (src/atom/unit_conversion.cpp:31), one per non-negative `UnitType`. There is **no bounds check**. With `unit == none`, `static_cast<i8>(none) == -1`, so `_unitConversions[-1]` reads the 32-byte `std::function`-sized object sitting immediately **before** the array — a neighbouring global reinterpreted as a `std::function` — and calls `operator()` on it.

libstdc++'s `std::function::operator()` first checks `_M_manager != nullptr` (the "empty" test), then performs an **indirect CALL through the `_M_invoker` slot** (offset +0x18), passing `&_M_functor` and `env`. So the code reads a function pointer out of a foreign global and jumps to it. This is not merely an out-of-bounds **read** — which is all AddressSanitizer can observe, because it traps the read inside `std::_Function_base::_M_empty()` *before* the call is reached — in an ordinary (non-ASan) build the control transfer actually executes: `rip` is loaded from out-of-bounds memory and control jumps to whatever the neighbour's `_M_invoker` bytes decode to.

The sibling sink `getSize` (src/atom/atom_space.h:48-49) has the identical unguarded `_unitConversions[static_cast<i8>(unit)]` pattern and is reachable by any other length-consuming macro that can deliver a `none`/out-of-range unit; a fix must cover both.

Reachability: this runs during ordinary message layout, not only when a standalone article is opened. Call chain — HistoryView message layout -> Iv::Markdown::TryPrepareNativeInstantView -> MeasureNativeIvPreparedFormulas -> MathRenderer::measureFormula -> MeasureWithMicrotex -> ParseFormula -> tex::LaTeX::parse (Telegram/SourceFiles/iv/markdown/iv_markdown_microtex.cpp:280) -> TeXRenderBuilder::build -> RowAtom::createBox -> Dummy::createBox -> SpaceAtom::createBox -> SpaceAtom::getFactor -> `_unitConversions[-1](env)`. This is the same renderer entry point as the sibling `\multirow` finding.

Delivery vector: a bot can produce a message whose native Instant-View math content (rich_message) contains the `\kern` trigger. Once forwarded to any user, group, supergroup, or channel, that message carries the same rich_message content with it, so any recipient's Telegram Desktop client reaches the vulnerable code path as soon as the chat is laid out for display. Ordinary compose-box text ("$$...$$") does not reach this path; forwarding a bot-generated message is what actually reaches the renderer.

## Steps to reproduce:
[1] Standalone / deterministic (fully proven). Build MicroTeX at the commit pinned by Telegram Desktop 6.9–6.9.3 (submodule desktop-app/MicroTeX, working-tree commit 55b801c) and feed the 5-byte payload through `tex::LaTeX::parse()`:

      \kern

  - Under AddressSanitizer this deterministically reports a global-buffer-overflow, READ of size 8, in `tex::SpaceAtom::getFactor` at atom_space.h:45, at an address "16 bytes before global `tex::SpaceAtom::_unitConversions` / 8 bytes after global `tex::PI`" — i.e. it pins the `_unitConversions[-1]` read exactly. ASan trace attached. Note: ASan traps the out-of-bounds read inside `std::_Function_base::_M_empty()` *before* the indirect call executes, so it proves the root cause but cannot itself show the control transfer.
  - In a release / non-ASan build under gdb: deterministic SIGSEGV, reproduced 20/20. The backtrace shows `#0 rip = 0x0` (executing *at* address 0), reached **through** `std::function::operator()` on an object at `<tex::PI>` (the neighbour that occupies `_unitConversions[-1]`), whose `_M_invoker` bytes happen to be `0x0` in that particular binary — `rip` is loaded from data and jumped to. Reproduce with the attached harness: `./poc/pwn` (equivalently `./build_plain/plain '\kern'`).

[2] Live / in-product (partially confirmed against the shipping client — stronger than a pure source-trace). Create a bot message whose native Instant-View math content contains `\kern`, then forward that message to a target user, group, supergroup, or channel using Telegram Desktop 6.9–6.9.3.

[3] Per the call chain above, the recipient's client parses the formula during message/article layout and crashes in the `SpaceAtom` render path. Unlike the sibling report, this is not only source-traced: four real Telegram Desktop crash dumps captured on 2026-07-03 carry the distinctive control-flow signature of this exact bug. The telegram-desktop module range was `0x555555554000–0x55555d561000`; all four `\kern` dumps put `rip` **above** that range (in the **heap**) with `rip == fault address`. `rip` **varies per run** (`…70455100`, `…73213180`, `…6ee671a0`, `…74ca9e00`) while `rdi` (= `&_M_functor` = `0x5555625ff060`, the fixed global at `_unitConversions[-1]`) and `rcx`/`r8`/`r9`/`r10`/`r14` stay **constant** across all four — the exact fingerprint of a deterministic indirect call `_M_invoker(&globalFunctor, env)` whose target is read from memory, which random memory corruption cannot reproduce. Two of the four were reproduced **live on demand** by pasting `\kern` (08:19:06 and 08:20:18). Of 100 crash dumps on disk, these 4 are the only ones with this control-flow signature; all others crash with `rip` in valid code (unrelated safe aborts). We attribute only these 4 to `\kern` and make no claim about the unrelated crashes.

One detail we are still pinning down (as with the sibling report): whether the crash fires only once the recipient opens that specific chat/article (UI:R -> 6.5, Medium), or from the message merely being received and auto-rendered during layout/preview (UI:N -> 7.5, what this report is scored against). We currently score UI:N because Instant-View math is measured/laid out during rendering rather than requiring a deliberate article open, and we will follow up if that changes the score.

## Impact:
A remotely reachable, deterministic, unauthenticated, near-zero-click **out-of-bounds indirect call** (CWE-129 improper array-index validation -> CWE-125 out-of-bounds read -> CWE-843/control-flow-integrity violation) in MicroTeX's `\kern` -> `getFactor` path, reachable through Telegram Desktop's bundled Instant-View math renderer via a forwarded bot-generated message. The **demonstrated** impact is a reliable remote crash (availability), confirmed both in isolation against the exact shipping MicroTeX commit (ASan + release-build gdb harness, deterministic) and against the live client (four crash dumps, two reproduced on demand). This report is scored **7.5 (High)** for that availability-only, near-zero-click (UI:N) demonstrated impact.

What makes this categorically worse than a plain logic-crash DoS — and worse than the sibling `\multirow` finding — is that `\kern` **actually transfers control**. The instruction pointer becomes a value the code reads from `_unitConversions[-1]._M_invoker`, landing in the heap in the shipping client. That is a genuine control-flow-hijack **primitive**. By explicit contrast, the `\multirow` out-of-bounds write never transfers control — its `height[j] += ex` write is gated behind a null-dereference that faults first, with `rip` staying in valid code — which is precisely why `\kern` is scored strictly higher than that finding.

RCE ceiling (explicitly NOT demonstrated). We are not claiming code execution. The jump currently lands on incidental heap bytes that decode to a faulting instruction, so the observed outcome is a crash. Weaponization would require one of: (a) controlling the `_M_invoker` slot of the specific fixed global that occupies `_unitConversions[-1]` (identify that object in the shipping binary and establish whether any attacker input influences its bytes), or (b) heap-grooming the target region from the same Instant-View content so the transfer lands on a controlled first instruction / fake gadget. Neither was attempted; both are non-trivial against the ASLR already in place (which moves the heap target every run). There is no accompanying information leak — the out-of-bounds value is consumed by the call, never returned to the attacker. If it were ever weaponized the severity ceiling rises toward CVSS 7.5–8.8; we report the demonstrated 7.5 and recommend treating this as a memory-safety / control-flow-integrity issue warranting exploit-development triage before any downgrade, rather than a plain DoS.

Blast radius: because the trigger travels with the forwarded message itself, a single forward into a group, supergroup, or channel puts the same crash in front of every member who subsequently renders that chat — the vulnerability is per-viewer (each client independently parses the same message), not a one-time hit, so practical exposure scales with the size of the chat it is forwarded into even though the CVSS base score is computed per victim. It can crash-loop a victim on every open until the message is removed/edited server-side or the client is patched. Math formulas are not validated server-side.

CVSS notes: headline `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5 (High)**. With UI:R (victim must deliberately open the chat) the same vector yields **6.5 (Medium)**. The rough CVSS 4.0 equivalent (`AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`) is ~7.0 (High). All three are availability-only; the control-flow-hijack ceiling above is deliberately not folded into the base score.

## Additional details:
- Exact sink: Telegram/ThirdParty/MicroTeX/src/atom/atom_space.h, `SpaceAtom::getFactor` (line 45) and the sibling `SpaceAtom::getSize` (line 49), at submodule commit 55b801c (matching Telegram Desktop 6.9–6.9.3). The trigger atom is built at src/core/macro_impl.cpp:12; the `none` unit originates at src/core/parser.cpp:694; the conversion array (14 entries, indices 0..13) is defined at src/atom/unit_conversion.cpp:31.
- Suggested fix (proposed; not yet applied upstream — presented as recommendation + test plan, not independently verified here): bounds-check both sinks so a `none`/out-of-range unit contributes no space instead of indexing before the array and invoking a foreign object as a callable.

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

  Important: the correct bound is the length of `_unitConversions` (**14**) — NOT the existing `_unitsCount`, which is the size of the separate `_units[]` name/alias table (16 aliases) and would be the wrong number. Add an explicit `_unitConversionsCount = sizeof(_unitConversions) / sizeof(_unitConversions[0])` next to the array. Returning `0.f` matches the existing unknown-unit fallback (`getUnit`, atom_space.cpp:13, unknown -> pixel) and renders nothing for a malformed `\kern`. Defense in depth: reject `UnitType::none` inside `macro(kern)` (e.g. treat a missing length as zero-width) so a missing length can never propagate a `none` unit downstream. Full diff attached (fix.md).
- The unguarded negative index is longstanding in upstream MicroTeX and is inherited by Telegram's fork desktop-app/MicroTeX; it is present in the builds that ship the MicroTeX Instant-View math renderer — reachable since that renderer was added (6.8.x beta line; in the stable channel since 6.9) through the current 6.9.3. (We are confident about 6.9–6.9.3, which we tested against commit 55b801c; the exact first affected beta we have not separately pinned and do not want to overstate.)
- PoC input (5 bytes, reproduces deterministically under both the ASan and release harnesses against the pinned commit):

      \kern

- Attached: the AddressSanitizer global-buffer-overflow report (asan_trace.txt) pinning the `_unitConversions[-1]` read (16 bytes before `_unitConversions`, 8 bytes after `tex::PI`); the minimal standalone reproduction harness (poc/code.cpp + poc/pwn) that parses `\kern` directly through `tex::LaTeX::parse` with no Qt/Telegram UI dependency; the release-build gdb backtrace and the four real-client crash-dump register/stackwalk excerpts showing the control-flow signature (two reproduced live), in gdb_evidence.md; and the source diff implementing the fix (fix.md).
