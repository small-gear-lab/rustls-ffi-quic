# rustls-ffi-quic: design

Status: **works, experimental.** The QUIC API, the renaming, the ngtcp2 helper and a curl that uses them are built
and packaged (see the APT repository, <https://github.com/small-gear-lab/apt-packaging>). HTTP/3, and ECH over
HTTP/3, work against public servers. What is not done is listed under "Not done yet".

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

- **This repository** (`rustls-ffi-quic`): a detached copy, with no fork relationship on GitHub. It was made by
  cloning `rustls/rustls-ffi` and setting `main` to the tag `v0.15.7`, so all of the upstream history is in it;
  the remote `upstream` is the original, `origin` is this repository. It has two branches:
  - **`main`**: the upstream release it stands on, then our commits, **in the names that upstream uses**
    (`rustls_*`, and `rustls_quic_*` for the QUIC API). It can be offered upstream as it is, and every change
    is made here.
  - **`renamed`**: `main` plus one commit, what `downstream/rename-symbols.py` makes of its sources (the exported
    functions are `rustlsq_*`, the library `librustls_quic`, the pkg-config module `rustls-quic`). The packages are
    built from the tags on this branch. It is made again, not rebased, whenever `main` has moved
    (`downstream/make-renamed.sh`): the renaming conflicts with every change of a function.
- **A fork** of `rustls/rustls-ffi` for pull requests of the QUIC API: made when the API is worth offering (the commits
  of `main` that are about the API, as they are, without the renaming).
- ngtcp2 helper (`crypto/rustls/`, see below): a branch of an ngtcp2 fork, or a separate library
  `libngtcp2_crypto_rustls`.
- curl: patches in `packaging/curl/debian/patches/` of the APT repository.

Nothing is created on GitHub before it is confirmed.

### Following upstream

`main` is the upstream release it stands on (a tag such as `v0.15.7`) and our commits on top of it. A new upstream
release is followed by putting our commits on the new tag, which is a rebase and rewrites the history of `main`.
That is meant, and safe as long as what the packages are built from stays reachable: every commit that a deb is
built from gets a tag on `renamed` (`v0.15.7+quic2`: the upstream tag, `+quic`, a counter), and a tag keeps its commit
alive after `main` and `renamed` have moved on. `packaging/rustls-ffi-quic/REV` names that tag, not a hash.

`downstream/update-upstream.sh <tag>` moves `main`, on a branch, without touching it:

1. fetches the tag, finds the upstream release `main` stands on, checks that the new one comes after it;
2. cherry-picks the commits of `main` since then onto the new tag, on the branch `update/<tag>`. A conflict only in
   `librustls/src/rustls.h` is settled by making the header again with cbindgen, as it is generated; a file that we
   delete but that the release changed (the CI of rustls-ffi) stays deleted; any other conflict stops the script with
   the way back printed;
3. makes `src/rustls.h` again if the release changed what the carried code gives, and runs the tests (`--no-test`
   skips them);
4. prints what is left to do by hand:

        git switch main && git reset --hard update/<tag>
        downstream/make-renamed.sh --test                # the branch "renamed": main plus the renaming
        git tag <tag>+quic<N> renamed
        git push --force-with-lease origin main renamed <tag>+quic<N>

   `--force-with-lease` stops the push if someone else pushed in the meantime.

`downstream/make-renamed.sh [--test] [<branch>]` makes `renamed` from `main` (or another branch) by running
`rename-symbols.py` and cbindgen, and commits the result as the one commit of the branch.

**A change** (the peer certificate for pinning over QUIC, say) is a normal commit on `main`, in the upstream names;
then `downstream/make-renamed.sh` makes `renamed` again. The CI runs the tests on `main`, and also applies the renaming
to a copy of it and runs them again, so a change that the renaming cannot carry is seen on `main`.

The two scripts were tried by moving this repository from `v0.15.7` to `v0.15.6` and back: the tree of `main` that
came out is the one that went in (`UPDATE_UPSTREAM_ANY_DIRECTION=1` allows the move to an older release, for that
test), and `renamed` made from it is the old one.

What the scripts do not do is the packaging: `version=` and `srcversion=` in `packaging/rustls-ffi-quic/build.sh`, a
changelog entry, `./build.sh fetch <tag>+quic<N>`, `./build.sh build`, and the soname, which carries the whole upstream
version (`librustls_quic.so.0.15.7`), so a new upstream release is a new package name, `librustls-quic<version>`.
A change of the C API of upstream that the QUIC API or the ngtcp2 helper depends on shows as a failing test or build;
look at the release notes of rustls-ffi first.

To offer the QUIC API upstream, the commits of `main` that are about it are the ones to put on a branch of a fork of
`rustls/rustls-ffi`, as they are: `main` has no renaming in it.

## Names

| What | Name |
|---|---|
| repository, source package, crate | `rustls-ffi-quic` |
| library | `librustls_quic.so.<soname>` |
| Debian packages | `librustls-quic<ver>`, `librustls-quic-dev` |
| header | `rustls-quic/rustls.h` (and `rustls-quic/rustls_upstream_names.h`) |
| pkg-config module | `rustls-quic` |
| exported C functions | `rustlsq_<name>` (was `rustls_<name>`) |

The version differs from upstream's (for example `0.15.8-quic.1`), and the soname carries the whole version, as
in the `librustls0.15.7` package.

## Symbol renaming

A library with the same exported `rustls_*` functions would interpose with upstream `librustls` when both are loaded
in one process (curl pulls libraries in through other libraries, so this can happen). The file names alone do not
prevent it, so every exported **function** is renamed:

- `rustls_X` becomes `rustlsq_X`: one to one, so it cannot collide with a new function. The prefix
  `rustls_quic_` was the first idea and does not work: the QUIC API is named after its object
  (`rustls_quic_connection_free`), and the renamed `rustls_connection_free` would be the same name.
- Measured on rustls-ffi 0.15.7: 146 distinct functions in `rustls.h` (142 exported dynamic symbols); with the QUIC API
  155 and 151. The built `librustls_quic.so` exports 151 symbols, all `rustlsq_*`, none `rustls_*`.
  The 33 struct and enum names and the 10 callback typedef names do not take part in linking and stay as they are.
  Function declarations have `(` right after the name, callback typedefs have `)` (`(*rustls_x_callback)(`), so a
  regex tells them apart.
- Done by `downstream/rename-symbols.py`, not by hand: on `main` it is a script only, and the branch `renamed` is
  what it makes of `main`, made again whenever `main` has moved (it can be run twice,
  and `--check` says whether it would change anything). It rewrites the Rust sources, the tests and the website
  content, and writes `rustls_upstream_names.h`; the header is then made by cbindgen from the renamed sources.
- Symbol versioning was considered as an alternative and not tried (unproven for a Rust `cdylib`; an unversioned
  reference could still bind to the wrong library).

### curl side

curl's `lib/vtls/rustls.c` calls 61 distinct `rustls_*` functions (97 calls). Rather than rewriting them:

1. `rustls_upstream_names.h`, included at the end of the header, carries `#define rustls_foo rustlsq_foo` for every
   function.
2. curl's `configure` looks for pkg-config `rustls-quic` first and falls back to `rustls`. The module's Cflags put
   `rustls-quic/` on the include path, so `#include <rustls.h>` finds the renamed header, and the library check
   uses `rustlsq_supported_hpke` in `librustls_quic`.
3. The code that uses the QUIC API is in `#ifdef USE_HTTP3`; `configure` turns QUIC on only when the library has
   `rustlsq_quic_client_connection_new`.

So curl still builds against plain rustls-ffi, and with `rustls-quic` its objects no longer refer to upstream's
names. Checked with curl 8.23.0: against `rustls-quic` libcurl refers to 67 `rustlsq_*` functions and no `rustls_*`
one, and does HTTP/3 and ECH; against plain rustls-ffi 0.15.7 it builds without QUIC and refers to 58 `rustls_*`
functions. Both builds are to be checked when packaging. The CMake build of curl is not covered yet. Rewriting every call site instead remains possible if the headers
approach turns out to be a problem.

## The ngtcp2 side

curl's QUIC code (`lib/vquic/`) supports ngtcp2 and quiche only, and `vquic-tls.c` has branches for OpenSSL, GnuTLS
and wolfSSL. ngtcp2 asks the TLS library for the **secrets** of each encryption level
(`ngtcp2_crypto_derive_and_install_rx/tx_key`) plus HKDF, AEAD and header-protection primitives
(41 declarations in `ngtcp2_crypto.h`). `rustls::quic` returns finished key objects and does not show the secrets.

How it is bridged:

- the traffic secrets come through Rustls' `KeyLog`: the connection works on a copy of the config whose key log keeps
  the secrets of this connection (`rustlsq_quic_connection_secret`) and passes every line on to the key log the
  config had;
- HKDF, AEAD and header protection are OpenSSL's libcrypto, as in ngtcp2's own quictls helper;
- the helper is `crypto/rustls/ngtcp2_crypto_rustls.c` of the package `ngtcp2-crypto-rustls` (it is built from
  ngtcp2's `crypto/shared.c` and this file; the file is derived from `crypto/quictls/quictls.c`).

What was open, and is settled:

- the `KeyLog` secret arrives before ngtcp2 needs the key: each secret exists from the moment the handshake bytes
  that give it have been read, which is before `write_hs` reports the keys (measured, and checked by a test);
- the Retry integrity tag is an AEAD operation that ngtcp2 does with the primitives of the helper, not a part of
  `rustls::quic`; it is not tried against a server that sends a Retry yet;
- `write_hs` has to be called after every `read_hs`, or the handshake bytes of two levels run together.

## Done, and not done yet

Done:

1. The QUIC C API (`librustls/src/quic.rs`), with a test that runs a handshake against a `rustls::quic` server.
2. The ngtcp2 helper, tried with a small client against cloudflare.com, www.google.com and quic.nginx.org (the
   handshake is confirmed by the server), and a failure test with a CA that does not match (alert 48).
3. curl: the `USE_RUSTLS` branch of `vquic-tls.c` and `cf-ngtcp2*.c`, and the build system. `curl --http3-only` works,
   so does `--ech true` over HTTP/3 (`sni=encrypted`).
4. Packages: `librustls-quic`, `libngtcp2-crypto-rustls`, and a Rustls flavour of curl.

Not done yet:

- **0-RTT and session resumption**: every connection does the full handshake; the early data keys of `rustls::quic`
  are not exposed.
- **Retry** and **key update** are not exercised: a transfer of about 1 MB is the longest one tried.
- **Server side**: client connections only.
- **NTLM**: needs DES from a TLS library. Options are a curl patch with an internal DES, NTLMv2 only, or
  `gss-ntlmssp`.
- **Certificate pinning** and **`--capath`**: possible as curl patches (`rustls_certificate_get_der`, `add_pem` exist
  in rustls-ffi); for pinning over QUIC this library needs a function that returns the peer's certificate.
- Sending the QUIC API upstream (see "Following upstream"), and the ngtcp2 helper to ngtcp2.

## Licensing

rustls-ffi is Apache-2.0 OR ISC OR MIT. The upstream license files are kept unchanged, the additions are
Copyright (c) 2026 Small Gear Lab and Marie under the same three licenses (see `NOTICE`). The upstream history
is kept so that the origin of every line is visible.
