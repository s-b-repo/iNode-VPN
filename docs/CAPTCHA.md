# CAPTCHA analysis — H3C iNode SSL VPN (`SSLVPN-Gateway/7.0`)

> Authorised interoperability / security testing against a gateway the author
> controls. Findings below were verified first-hand against a live gateway.

## 1. How the gateway uses the CAPTCHA

When `gatewayinfo` advertises `supportvldimg=true`, login is gated on a
validation image:

1. `GET /svpn/index.cgi` → `302` → `GET /client_getinfo.cgi` returns the
   capability XML (flags as `true`/`false`; URLs in a `<url>` block).
2. `GET /vldimg.cgi` returns a **96×24 24-bit BMP** and sets
   `Set-Cookie: svpnginfo=vld@<hex>; path=/`. The answer is bound to that
   server-side session.
3. `POST /_xml/login.cgi` with `request=`+urlencoded `<data>` login XML
   (`<vldCode>` = the answer), `Cookie: svpnginfo=vld@…`.

**Reply oracle** — the response distinguishes the two failure modes:

| Reply `replyMessage`            | Meaning                                            |
|---------------------------------|----------------------------------------------------|
| `Verify code error`             | CAPTCHA wrong/missing — login **never reached** the password check |
| `Authentication failed. Reason: incorrect username or password …` | CAPTCHA **accepted**; credentials checked |

## 2. The weakness

The image provides effectively **no protection against automation**:

* **4 characters**, each a **solid, saturated, distinct colour** on a near-white
  background, **spatially separated**, with no warping, rotation, or overlap.
  The only obfuscation is isolated speckle noise.
* Therefore segmentation is trivial: `ink = (pixel not near-white)`, drop
  connected components smaller than ~6 px (kills speckle), split on the
  vertical projection’s gaps → four clean glyphs → OCR each one.
* Off-the-shelf **`tesseract`** (zero training) solves a clean 4-char read
  ~11/12 of the time after that preprocessing.
* Per-attempt OCR need not be perfect, because **the reply is a success
  oracle**: a `fetch → solve → submit` loop retries with a *fresh* image until
  the gateway stops returning `Verify code error`. This converges in a few
  attempts and is fully unattended.

Confirmed end-to-end: OCR’d codes (e.g. `YLKY`, `WIIH`) were accepted by the
live gateway with no human in the loop.

### Why retrying is cheap / quiet
Attempts whose OCR is wrong fail at the **CAPTCHA stage** and never reach the
password check — so the retry loop does **not** generate failed-password events
until a captcha is actually solved. The CAPTCHA adds latency, not security.

### Short TTL — hurts humans, not bots
The image is **single-use with a short server-side TTL**: a *correct* answer
submitted ~20–40 s after the image was fetched is rejected `Verify code error`,
while the same answer submitted within ~1 s is accepted. This is presumably
meant to bound brute-force, but it has the perverse effect of penalising
*human* solvers (who need seconds to read+type) while an OCR bot that submits in
~1 s sails through. The solver therefore submits immediately and never wastes a
TTL window on a low-confidence read (`session.py` skips and re-fetches instead).

## 3. Proof of concept

* Standalone: [`../captcha_lab.py`](../captcha_lab.py)
  * `python captcha_lab.py accuracy <host:port> 12` — solver hit-rate, no logins
  * `python captcha_lab.py reliable <host:port> <user> <pass>` — oracle-driven
    auto-defeat, then prints the real post-captcha credential outcome
* In the client: `h3csvpn/captcha.py` (stdlib BMP decode + ANSI preview +
  optional `tesseract` solver), wired into `session.py` and enabled by default
  (`--auto-captcha`, persisted in `~/.config/h3csvpn/config.json`).

## 4. Recommended mitigations (defensive)

This kind of CAPTCHA should not be relied on as an auth factor. If kept:

* Use a **distortion-based** CAPTCHA (warping, overlapping glyphs, connected
  arcs, varied baselines) or, better, drop the image CAPTCHA in favour of a
  real second factor (TOTP/push/SMS — the gateway already supports a challenge
  flow).
* Do **not** use per-character solid colours or fixed spacing (defeats
  segmentation). Add background texture that is hard to threshold from ink.
* **Rate-limit and lock out** by client IP *and* account on repeated
  `Verify code error` — the current behaviour lets an attacker pull unlimited
  fresh images and brute the OCR for free.
* Bind the CAPTCHA to a short TTL and make it strictly single-use.
* Most importantly, ensure the **credential** brute-force protections are
  independent of the CAPTCHA, since the CAPTCHA can be bypassed by automation.
