use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    let ndpi_dir = manifest_dir.join("vendor/nDPI");
    let ndpi_include_dir = ndpi_dir.join("src/include");
    let ndpi_lib_dir = ndpi_dir.join("src/lib");

    ensure_ndpi_sources_present(&ndpi_dir, &ndpi_include_dir, &ndpi_lib_dir);

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    let generated_include_dir = out_dir.join("include");
    fs::create_dir_all(&generated_include_dir)
        .expect("failed to create generated include directory");

    println!("cargo:rerun-if-changed=build.rs");
    let ndpi_define_header = ndpi_dir.join("windows/src/ndpi_define.h");

    println!("cargo:rerun-if-changed={}", ndpi_define_header.display());

    copy_public_headers(&ndpi_include_dir, &generated_include_dir);
    write_ndpi_config_header(&generated_include_dir);
    write_ndpi_define_header(&ndpi_define_header, &generated_include_dir);

    let c_sources = collect_c_sources(&ndpi_lib_dir);

    let mut build = cc::Build::new();
    // nDPI is vendored third-party C code. Keep the Cargo build quiet unless
    // there is an actual compile failure.
    build.warnings(false);
    build.files(&c_sources);
    build.include(&generated_include_dir);
    build.include(&ndpi_include_dir);
    build.include(&ndpi_lib_dir);
    build.include(ndpi_lib_dir.join("third_party/include"));
    build.define("NDPI_LIB_COMPILATION", None);
    build.define("_DEFAULT_SOURCE", Some("1"));
    build.define("_GNU_SOURCE", Some("1"));
    build.flag_if_supported("-std=gnu11");
    build.flag_if_supported("-fPIC");
    build.flag_if_supported("-Wno-unused-function");
    build.flag_if_supported("-Wno-unused-parameter");
    build.flag_if_supported("-Wno-attributes");
    build.flag_if_supported("-Wno-discarded-qualifiers");
    build.flag_if_supported("-Wno-maybe-uninitialized");
    build.compile("ndpi");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        println!("cargo:rustc-link-lib=m");
    }

    println!("cargo:include={}", generated_include_dir.display());
}

fn ensure_ndpi_sources_present(ndpi_dir: &Path, ndpi_include_dir: &Path, ndpi_lib_dir: &Path) {
    if ndpi_include_dir.is_dir() && ndpi_lib_dir.is_dir() {
        return;
    }

    panic!(
        "nDPI source tree not found at '{}'. This repository expects vendored nDPI sources.",
        ndpi_dir.display()
    );
}

fn copy_public_headers(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source).expect("failed to read nDPI include directory") {
        let entry = entry.expect("failed to read include directory entry");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("h") {
            let file_name = path.file_name().expect("header without file name");
            fs::copy(&path, destination.join(file_name))
                .expect("failed to copy nDPI public header");
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn write_ndpi_config_header(generated_include_dir: &Path) {
    let header =
        "#pragma once\n\n#define NDPI_GIT_RELEASE \"5.0.0\"\n#define NDPI_GIT_DATE \"unknown\"\n";

    fs::write(generated_include_dir.join("ndpi_config.h"), header)
        .expect("failed to write ndpi_config.h");
}

fn write_ndpi_define_header(ndpi_define_header: &Path, generated_include_dir: &Path) {
    let mut rendered =
        fs::read_to_string(ndpi_define_header).expect("failed to read nDPI ndpi_define.h");

    rendered = set_define_value(&rendered, "NDPI_API_VERSION", "0");
    rendered = set_define_value(&rendered, "NDPI_MAJOR", "5");
    rendered = set_define_value(&rendered, "NDPI_MINOR", "0");
    rendered = set_define_value(&rendered, "NDPI_PATCH", "0");

    fs::write(generated_include_dir.join("ndpi_define.h"), rendered)
        .expect("failed to write ndpi_define.h");
}

fn set_define_value(contents: &str, define_name: &str, define_value: &str) -> String {
    let mut out = String::with_capacity(contents.len());

    for line in contents.lines() {
        let trimmed = line.trim_start();
        let mut parts = trimmed.split_whitespace();
        let is_target_define = parts.next() == Some("#define") && parts.next() == Some(define_name);

        if is_target_define {
            out.push_str(&format!("#define {} {}", define_name, define_value));
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }

    out
}

fn collect_c_sources(ndpi_lib_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    files.extend(collect_c_sources_from_dir(ndpi_lib_dir));
    files.extend(collect_c_sources_from_dir(&ndpi_lib_dir.join("protocols")));
    files.extend(collect_c_sources_from_dir(
        &ndpi_lib_dir.join("third_party/src"),
    ));
    files.extend(collect_c_sources_from_dir(
        &ndpi_lib_dir.join("third_party/src/hll"),
    ));

    files.sort();

    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }

    files
}

fn collect_c_sources_from_dir(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = WalkDir::new(dir)
        .max_depth(1)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("c"))
        .collect();

    files.sort();
    files
}
