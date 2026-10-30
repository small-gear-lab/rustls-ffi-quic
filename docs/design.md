# rustls-ffi-quic: design

Status: **plan, nothing implemented yet.** The first step is a throw-away local experiment (see "Plan").

## Goal

A curl built on Rustls that has **QUIC / HTTP/3**, **ECH**, and no GPL library in the link, so that it can be
shipped from the small-gear-lab APT repository.

## Why

| Backend | ECH | HTTP/3 | NTLM | Problem |
|---|---|---|---|---|
| OpenSSL 3.5 (current `curl`) | no | yes (ngtcp2) | yes | no ECH before OpenSSL 4.0 |
| wolfSSL (Ubuntu 5.9.1) | yes | possible, not in Ubuntu | yes | GPL-3+ (with a GPL-2 exception): not wanted |
| Rustls via rustls-ffi 0.15.7 | yes | **no** | no | rustls-ffi exposes no QUIC |

The Rust crate `rustls` has a `quic` module (`rustls::quic`, 0.23.46: `ClientConnection`, `read_hs`, `write_hs`
returning a `KeyChange`, `quic_transport_parameters`, `zero_rtt_keys`, `Keys::initial`, `PacketKey`,
`HeaderProtectionKey`). rustls-ffi 0.15.7 does not export any of it. So the missing piece is a **C ABI over
`rustls::quic`**. Rustls itself needs no change.

## Repositories

- **Fork** of `rustls/rustls-ffi` on GitHub (branch `quic`): the QUIC C API only, as plain upstream-style
  commits, to be offered as pull requests. Keeps upstream's names.
- **This repository** (`rustls-ffi-quic`): a detached copy, with no fork relationship on GitHub. It was made by
  cloning `rustls/rustls-ffi` and setting `main` to the tag `v0.15.7`, so all of the upstream history is in it;
  the remote `upstream` is the original, `origin` is this repository. It adds what upstream would not take: the
  renamed exported symbols, `rustls-quic.h`, `librustls_quic`, the pkg-config file. The QUIC commits are carried
  over from the fork.
- ngtcp2 helper (`crypto/rustls/`, see below): a branch of an ngtcp2 fork, or a separate library
  `libngtcp2_crypto_rustls`.
- curl: patches in `packaging/curl/debian/patches/` of the APT repository.

Nothing is created on GitHub before it is confirmed.

### Following upstream

New upstream releases are taken with `git fetch upstream` and a rebase of our commits onto the new tag. The
symbol renaming is a script (see below) that is run again after each rebase, so that it never has to be merged by
hand. The upstream license files are never edited here; our copyright lines are in `NOTICE`.

## Names

| What | Name |
|---|---|
| repository, source package, crate | `rustls-ffi-quic` |
| library | `librustls_quic.so.<soname>` |
| Debian packages | `librustls-quic<ver>`, `librustls-quic-dev` |
| header | `rustls-quic.h` |
| pkg-config module | `rustls-quic` |
| exported C functions | `rustls_quic_<name>` (was `rustls_<name>`) |

The version differs from upstream's (for example `0.15.8-quic.1`), and the soname carries the whole version, as
in the `librustls0.15.7` package.

## Symbol renaming

A library with the same exported `rustls_*` functions would interpose with upstream `librustls` when both are loaded
in one process (curl pulls libraries in through other libraries, so this can happen). The file names alone do not
prevent it, so every exported **function** is renamed:

- `rustls_X` becomes `rustls_quic_X`: one to one, so it cannot collide with a new function.
- Measured on rustls-ffi 0.15.7: 146 distinct functions in `rustls.h` (142 exported dynamic symbols).
  The 33 struct and enum names and the 10 callback typedef names do not take part in linking and stay as they are.
  Function declarations have `(` right after the name, callback typedefs have `)` (`(*rustls_x_callback)(`), so a
  regex tells them apart.
- Done by a script from the header and the Rust `#[no_mangle]` / cbindgen names, not by hand, and run again on
  every upstream update.
- Symbol versioning was considered as an alternative and not tried (unproven for a Rust `cdylib`; an unversioned
  reference could still bind to the wrong library).

### curl side

curl's `lib/vtls/rustls.c` calls 61 distinct `rustls_*` functions (97 calls). Rather than rewriting them:

1. `rustls-quic.h` carries `#define rustls_foo rustls_quic_foo` for every function.
2. curl's build looks for pkg-config `rustls-quic` first and falls back to `rustls`; with `rustls-quic` found it
   includes `rustls-quic.h`, otherwise `rustls.h`.
3. The code that uses the new QUIC functions is in `#ifdef` and only built with `rustls-quic`.

So curl still builds against plain rustls-ffi, and with `rustls-quic` its objects no longer refer to upstream's
names. Both builds are checked when packaging. Rewriting every call site instead remains possible if the headers
approach turns out to be a problem.

## The ngtcp2 side (the unknown part)

curl's QUIC code (`lib/vquic/`) supports ngtcp2 and quiche only, and `vquic-tls.c` has branches for OpenSSL, GnuTLS
and wolfSSL. ngtcp2 asks the TLS library for the **secrets** of each encryption level
(`ngtcp2_crypto_derive_and_install_rx/tx_key`) plus HKDF, AEAD and header-protection primitives
(41 declarations in `ngtcp2_crypto.h`). `rustls::quic` returns finished key objects and does not show the secrets.

Bridge under test:

- get the traffic secrets through Rustls' `KeyLog` (rustls-ffi already has `set_key_log`);
- HKDF / AEAD / header protection from aws-lc-rs, which is linked in anyway;
- the helper is `crypto/rustls/rustls.c`, next to `crypto/wolfssl/wolfssl.c` (545 lines) and the other backends.

Open questions:

- whether the `KeyLog` secret arrives before ngtcp2 needs the key;
- the Retry integrity tag (`rustls::quic` has none, it is another AEAD operation);
- 0-RTT and session resumption.

If the secrets cannot be had in time, the fallback is a different shape of helper that uses the `PacketKey` objects
directly, which means more of the ngtcp2 crypto layer is replaced.

## Plan

1. Local, throw-away: copy rustls-ffi 0.15.7, add a minimal QUIC C API (`ClientConnection::new_with_alpn`,
   `read_hs`, `write_hs` / `KeyChange`, transport parameters), and complete a QUIC TLS handshake against a server
   from a small C program.
2. ngtcp2 `crypto/rustls` helper with the `KeyLog` bridge; check Retry and 0-RTT.
3. curl: `USE_RUSTLS` branch in `vquic-tls.c` and the build-system changes above.
4. Package `librustls-quic` and a `curl` flavour that uses it in the APT repository.
5. Only then create the GitHub repositories and send the QUIC API upstream.

Each step ends with a decision whether the next one is worth it.

## Still open

- NTLM: needs DES from a TLS library. Options are a curl patch with an internal DES, NTLMv2 only, or `gss-ntlmssp`.
  Not needed for the QUIC work.
- Certificate pinning and `--capath`: possible as curl patches (`get_peer_certificate`, `add_pem` exist in
  rustls-ffi).
- Whether the `curl` package becomes this flavour for good or a separate package is kept next to the OpenSSL one.

## Licensing

rustls-ffi is Apache-2.0 OR ISC OR MIT. The upstream license files are kept unchanged, the additions are
Copyright (c) 2026 Small Gear Lab and Marie under the same three licenses (see `NOTICE`). The upstream history
is kept so that the origin of every line is visible.
