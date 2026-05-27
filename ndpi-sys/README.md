# ndpi-sys

Rust `-sys` crate that builds **nDPI 5.0** from the vendored source tree at
`vendor/nDPI`.

## What this crate does

- Compiles nDPI C sources with `cc`.
- Generates required nDPI config headers (`ndpi_config.h`, `ndpi_define.h`) in
  `OUT_DIR`.
- Exposes raw FFI bindings in `src/bindings.rs`.

## Build requirements

- A C toolchain (`cc`, `ar`) available in your environment.
- On Unix-like platforms, links against `libm`.

## Notes

- Optional nDPI integrations (PCRE2, MaxMindDB, nBPF, external libgcrypt, etc.)
  are not enabled in this build.
- TLS signature algorithm handling is disabled (matching nDPI default unless
  explicitly enabled at configure time).
- The upstream nDPI `tests/`, `fuzz/`, and `dga/` trees are not vendored, as
  this crate builds only the library sources. DGA runtime code/data used by the
  library remains under `src/lib`.
