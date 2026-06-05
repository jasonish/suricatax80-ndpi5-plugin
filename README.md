# Experimental Suricata 8.0 nDPI 5 Plugin

This is an example of what a Rust plugin, wrapping a C library could look like
as a Suricata 8.0.x plugin.

Note that this is an experimental proof of concept. Suricata 9.0 will have
proper supported bindings for such plugins.

## Downloads

A pre-built Linux x86_64 plugin (`ndpi.so`) can be downloaded from the
[releases](https://github.com/jasonish/suricatax80-ndpi5-plugin/releases)
page.

## Building

MSRV: Rust 1.75.0.

This crate depends on the `suricatax80-plugin-utils` crate.

```sh
cargo build --release
```

The plugin shared object is written to:

```text
target/release/libndpi.so
```

Configure Suricata with the resulting plugin path, for example:

```yaml
plugins:
  - /path/to/target/release/libndpi.so
```
