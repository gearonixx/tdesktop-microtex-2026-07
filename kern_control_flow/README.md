## Control-Flow Hijack in MicroTeX

A 5-byte LaTeX payload deterministically
redirects the instruction pointer in the shipping version of Telegram Desktop to an
out-of-bounds function pointer, transferring control into the heap.

The vulnerability exists since Telegram Desktop version 6.8.2 beta.

Math formulas are not validated server-side.
I was able to bypass the server-side validation entirely.


## Reproduce

Create a Telegram bot that replies with the following TeX payload (you can create one
yourself or use an existing AI bot; I used https://t.me/claw).

```tex
\kern
```

## Impact

Forwarding this single message is sufficient to crash any recipient, including individual
users, groups, channels, and supergroups, in real time.

## Demonstration

```bash
./poc/pwn
```
---


I reproduced the crash on the
official Telegram Desktop release build.

6.9.3 Linux x86_64

Crash reports (Crash ID's):


```
741c742f-1c01-4a67-9c924eb9-3a3d19c8
6aaaca51-1668-4e03-8281079b-66a3b403
485b2028-beb0-4e8b-20ed62bf-8c6f032c
```

## Root cause

A `\kern` command without a length argument produces a `SpaceAtom` whose unit is
`UnitType::none`. The `none` enumerator has the integer value **−1**. During rendering,
`SpaceAtom::getFactor` evaluates

```cpp
_unitConversions[static_cast<i8>(unit)](env)
```

which becomes `_unitConversions[-1](env)`. This indexes one element before the global
array of `std::function` objects, interprets the adjacent memory as a
`std::function<float(const Environment&)>`, and immediately invokes it.

In the shipping client, the invoker pointer read from this out-of-bounds slot resolves to
a heap address that changes on every execution. Control is transferred to that address,
and the process crashes while attempting to execute heap data.

This behavior was confirmed in `gdb` on the release build and by four independent
Telegram Desktop crash dumps, two of which were reproduced live on demand. This
constitutes a control-flow hijack primitive resulting from an out-of-bounds function
pointer invocation.