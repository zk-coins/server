//! Compile `proto/kernel/v1/kernel.proto` into the `kernel.v1` package.
//!
//! Paths are anchored at this crate's manifest dir so the workspace can
//! be built from any cwd. The proto file itself is owned by the workspace
//! root (`proto/…`) and is not duplicated here.

use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto = manifest_dir.join("../proto/kernel/v1/kernel.proto");
    let include = manifest_dir.join("../proto");

    println!("cargo:rerun-if-changed={}", proto.display());

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto], &[include])?;

    Ok(())
}
