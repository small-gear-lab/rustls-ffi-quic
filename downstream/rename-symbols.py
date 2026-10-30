#!/usr/bin/python3 -I
"""Rename the exported C functions of rustls-ffi from `rustls_*` to `rustlsq_*`.

Usage: downstream/rename-symbols.py [--prefix rustlsq_] [--check]

rustls-ffi-quic is installed next to rustls-ffi, and a process can load both (curl
reaches its TLS library through other libraries). Two libraries that export the same
function names would then answer for each other, so every exported *function* gets a
prefix of its own. Types, enum values and macros are not symbols and keep their names.

The names are taken from the functions that `librustls/src/rustls.h` declares. The
change is one to one (`rustls_X` -> `rustlsq_X`), so a new function cannot collide with an
old one. It is a function of the sources, so after taking a new upstream release the script
is run again instead of the change being merged by hand. Run it twice and the second run
changes nothing.

It rewrites the Rust sources and tests, the C tests, and the documentation under
website/content. The header is written by cbindgen from the renamed sources: run
`cbindgen --output src/rustls.h` in librustls afterwards. It also writes
librustls/src/rustls_upstream_names.h, which maps the upstream names to the new ones, so that
C code written against rustls-ffi (curl) compiles unchanged, and makes the few changes to
cbindgen.toml and librustls/Cargo.toml that go with it (the header includes that file; the
library, the pkg-config module and the header directory get their own names).

--check changes nothing and exits 1 if a run would change something.
"""
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
prefix = "rustlsq_"
check = False
args = sys.argv[1:]
while args:
    a = args.pop(0)
    if a == "--prefix":
        prefix = args.pop(0)
    elif a == "--check":
        check = True
    else:
        sys.exit(__doc__)

header = root / "librustls/src/rustls.h"
names_header = root / "librustls/src/rustls_upstream_names.h"
text = header.read_text()
# declarations: the name is followed by `(` (a function pointer typedef has `)` after the name)
functions = sorted(set(re.findall(r"\b(rustls_[a-z0-9_]+)\(", text)))
if not functions:
    # already renamed: take the upstream names back from the mapping header
    functions = sorted(re.findall(r"^#define (rustls_[a-z0-9_]+) ", names_header.read_text(), re.M))
if not functions:
    sys.exit("no functions found in %s" % header)

pattern = re.compile(r"\b(%s)\b" % "|".join(map(re.escape, functions)))
roots = ["librustls/src", "librustls/tests", "tools", "website/content"]
suffixes = {".rs", ".c", ".h", ".md", ".txt", ".toml"}
skip = {"rustls_upstream_names.h"}

changed = []
for r in roots:
    for path in sorted((root / r).rglob("*")):
        if not path.is_file() or path.suffix not in suffixes or path.name in skip:
            continue
        try:
            old = path.read_text()
        except UnicodeDecodeError:
            continue
        new = pattern.sub(lambda m: prefix + m.group(1)[len("rustls_"):], old)
        if new != old:
            changed.append(path.relative_to(root))
            if not check:
                path.write_text(new)

mapping = ["/* The names of the functions of rustls-ffi, mapped to the ones this library exports.",
           " * Written by downstream/rename-symbols.py; do not edit. */",
           "#ifndef RUSTLS_UPSTREAM_NAMES_H", "#define RUSTLS_UPSTREAM_NAMES_H", ""]
mapping += ["#define %s %s" % (f, prefix + f[len("rustls_"):]) for f in functions]
mapping += ["", "#endif /* RUSTLS_UPSTREAM_NAMES_H */", ""]
new_names = "\n".join(mapping)
if not names_header.exists() or names_header.read_text() != new_names:
    changed.append(names_header.relative_to(root))
    if not check:
        names_header.write_text(new_names)

# cbindgen.toml and Cargo.toml: each edit is made only while the file does not have its result yet
def edit(path, old, new, done):
    f = root / path
    s = f.read_text()
    if done in s:
        return
    if old not in s:
        sys.exit("%s: cannot find the text to change (%r); upstream changed it?" % (path, old[:40]))
    changed.append(f.relative_to(root))
    if not check:
        f.write_text(s.replace(old, new, 1))


edit("librustls/cbindgen.toml", "usize_is_size_t = true",
     '# the names of the functions of rustls-ffi, mapped to the ones this library exports\n'
     'trailer = "#include \\"rustls_upstream_names.h\\""\n\nusize_is_size_t = true',
     "rustls_upstream_names.h")
cargo = "librustls/Cargo.toml"
edit(cargo, '[package.metadata.capi.header]\nname = "rustls"\nsubdirectory = false',
     '[package.metadata.capi.header]\nname = "rustls"\nsubdirectory = "rustls-quic"', 'subdirectory = "rustls-quic"')
edit(cargo, '[package.metadata.capi.library]\nname = "rustls"',
     '[package.metadata.capi.library]\nname = "rustls_quic"', 'name = "rustls_quic"')
edit(cargo, '[package.metadata.capi.pkg_config]\nname = "rustls"\nfilename = "rustls"',
     '[package.metadata.capi.pkg_config]\nname = "rustls-quic"\nfilename = "rustls-quic"', 'name = "rustls-quic"')
edit(cargo, 'asset = [{ from = "src/rustls.h", to = "" }]',
     'asset = [\n    { from = "src/rustls.h", to = "rustls-quic" },\n'
     '    { from = "src/rustls_upstream_names.h", to = "rustls-quic" },\n]',
     'rustls_upstream_names.h", to = "rustls-quic"')

print("%d functions, %d files %s" % (len(functions), len(changed), "would change" if check else "changed"))
if check and changed:
    sys.exit(1)
