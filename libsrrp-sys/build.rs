extern crate bindgen;

use std::{env, io};
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rustc-link-lib=static=srrp");
    println!("cargo:rerun-if-changed=wrapper.h");

    if cfg!(windows) {
        println!("cargo:rustc-link-lib=regex");
    }

    std::process::Command::new("git")
        .arg("clone")
        .arg("https://github.com/yonzkon/cio.git")
        .output()
        .expect("failed to clone cio");

    let mut cc_builder = cc::Build::new();
    add_c_files(&mut cc_builder, "../src");
    cc_builder.include("cio/src").compile("srrp");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn add_c_files(build: &mut cc::Build, path: impl AsRef<Path>) {
    // sort the C files to ensure a deterministic build for reproducible builds
    let dir = path.as_ref().read_dir().unwrap();
    let mut paths = dir.collect::<io::Result<Vec<_>>>().unwrap();
    paths.sort_by_key(|e| e.path());

    for e in paths {
        let path = e.path();
        if e.file_type().unwrap().is_dir() {
            // skip dirs for now
        } else if path.extension().and_then(|s| s.to_str()) == Some("c") {
            build.file(&path);
        }
    }
}
