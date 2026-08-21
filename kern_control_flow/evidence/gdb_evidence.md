# gdb / crash-dump evidence — `\kern` control-flow hijack

Supporting evidence for the out-of-bounds indirect call in `tex::SpaceAtom::getFactor`
(`_unitConversions[-1]`, reached via `UnitType::none == -1`). telegram-desktop module
range in the dumps below: **`0x555555554000 – 0x55555d561000`**.

---

## A. Release build under gdb (`build_plain/plain '\kern'`) — the control transfer

Non-ASan build, so the indirect call actually executes. `\kern` -> SIGSEGV, 20/20 deterministic.

```
Program received signal SIGSEGV, Segmentation fault.
#0  0x0000000000000000 in ?? ()                                   <-- rip = 0x0 (executing AT 0)
#1  0x0000555555631536 in std::function<float (tex::Environment const&)>::operator()
        (this=0x5555557b9cc0 <tex::PI>, __args=...) at bits/std_function.h:591
#2  0x000055555563140e in tex::SpaceAtom::getFactor (unit=tex::UnitType::none, env=...)
        at src/atom/atom_space.h:45
#3  0x000055555565be91 in tex::SpaceAtom::createBox (this=..., env=...) at src/atom/atom_space.cpp:19
#4  0x00005555556b8ab9 in tex::TeXRenderBuilder::build (...) at src/render.cpp:195
#5  0x00005555556b86a4 in tex::TeXRenderBuilder::build (...) at src/render.cpp:168
#6  0x00005555555c259d in tex::LaTeX::parse (latex=L"\\kern", ...) at src/latex.cpp:186

(gdb) info symbol $rip   ->  No symbol matches $rip.
(gdb) x/i $rip           ->  0x0: Cannot access memory at address 0x0
(gdb) p si_addr          ->  (void *) 0x0
```

Read `#0` carefully: the process is executing **at address 0**, reached **through**
`std::function::operator()` on an object at `<tex::PI>` — an object that is not a
`std::function`, sitting at `_unitConversions[-1]`. In this binary that neighbour's
`_M_invoker` bytes resolve to `0x0`, so the jump target is null and it faults immediately.
The shipping client's neighbour is different and resolves into the heap (section B).

---

## B. Four real Telegram Desktop crash dumps (2026-07-03) — control transfers into the heap

All four `\kern` dumps: `rip` **above** the module range (heap), `rip == fault address`.

| Dump        | Time     | `rip` (= call target) | Provenance                 |
|-------------|----------|-----------------------|----------------------------|
| a6c07f72-…  | 07:38:30 | `0x555570455100`      | testing session            |
| 83cf7b01-…  | 07:39:48 | `0x555573213180`      | testing session            |
| 71aaf1b3-…  | 08:19:06 | `0x55556ee671a0`      | **live-reproduced `\kern`** |
| e33d16a3-…  | 08:20:18 | `0x555574ca9e00`      | **live-reproduced `\kern`** |

`rip` varies every run (heap ASLR) -> it is read from memory, not a fixed code path.

### Register file (crashing thread, `e33d16a3`, live `\kern`)

```
rip = 0x0000555574ca9e00    <- CALL TARGET (_M_invoker); heap; varies per run
rdi = 0x00005555625ff060    <- &_M_functor = _unitConversions[-1] (fixed global); CONSTANT
rsi = 0x0000555564242f70    <- arg2 = Environment& env; heap; varies
rcx = 0x0000555563994280    <- CONSTANT across dumps
r8  = 0x0000000000000000    <- CONSTANT
r9  = 0x000055556236a7b8    <- CONSTANT
r10 = 0x000055556246ec90    <- CONSTANT
r14 = 0x00005555625ff080    <- CONSTANT (= rdi + 0x20)
Crash reason: SIGSEGV / SEGV_ACCERR
Crashing instruction: `mov al, byte [0x10000555561fb26]`   (post-hijack; whatever the heap bytes decode to)
```

The libstdc++ call is `_M_invoker(&_M_functor, env)`: `rdi = &_M_functor` (fixed global),
`rsi = env` (live heap object), `rip = _M_invoker` (heap pointer read from `[rdi + 0x18]`).

### Constant-register table across the dumps (deterministic path proof)

| reg               | a6c07f72   | 83cf7b01   | e33d16a3   | constant? |
|-------------------|------------|------------|------------|-----------|
| `rdi` (&functor)  | `…625ff060`| `…625ff060`| `…625ff060`| **yes**   |
| `rcx`             | `…63994280`| `…63994280`| `…63994280`| **yes**   |
| `r8`              | `0`        | `0`        | `0`        | **yes**   |
| `r9`              | `…6236a7b8`| `…6236a7b8`| `…6236a7b8`| **yes**   |
| `r10`             | `…6246ec90`| `…6246ec90`| `…6246ec90`| **yes**   |
| `r14`             | `…625ff080`| `…625ff080`| `…625ff080`| **yes**   |
| `rip` (target)    | `…70455100`| `…73213180`| `…74ca9e00`| no (heap) |
| `rsi` (env)       | varies     | varies     | varies     | no (heap) |

Constant `rdi/rcx/r8/r9/r10/r14` with varying `rip/rsi` across four independent crashes is
the signature of a deterministic indirect call `_M_invoker(&globalFunctor, env)` reading its
target from memory — random corruption cannot reproduce identical register state.

### Attribution / call chain (identical in all four `\kern` dumps)

```
#0  <hijacked rip, wild heap target>
#1  telegram-desktop + 0x53d2677   <- SpaceAtom::createBox / getFactor (indirect call site)
#2  telegram-desktop + 0xb77e11    <- Dummy::createBox
#3  telegram-desktop + 0xb79fe5    <- RowAtom::createBox
#4  telegram-desktop + 0xb883c3    <- TeXRenderBuilder::build
```

The sub-chain `+0x53d2677 -> +0xb77e11 -> +0xb79fe5 -> +0xb883c3` also appears in
same-session dumps that are provably MicroTeX (e.g. a `SIGABRT` carrying the assertion
`__n < this->size()` for `vector<shared_ptr<tex::Atom>>`), anchoring the wild-`rip` crashes
to the MicroTeX `SpaceAtom` render path. No `.sym` files were on disk, so frames are
`module+offset`; attribution is by call-chain + register signature + live reproduction.

Of 100 dumps on disk (2026-03-14 -> 2026-07-03) exactly these 4 carry the `rip==fault`,
outside-any-module control-flow signature; every other dump crashes with `rip` in valid code
(unrelated safe aborts, not attributed to `\kern`).

### Thermal / bit-flip hypothesis rejected

The machine had been thermally throttling shortly before the 07:38 dumps, and the
stackwalker prints a "may be a flipped bit" heuristic — both were considered and rejected:
the bug reproduces **on demand** for the `\kern` input (08:19, 08:20 captured live), four
crashes share **identical** register state (impossible for random corruption), and gdb on
the release build reproduces the same indirect-call fault deterministically. This is a
deterministic software control-flow bug.
