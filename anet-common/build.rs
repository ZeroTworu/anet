use std::io::Result;

fn main() -> Result<()> {
    let ci = std::env::var("CI").unwrap_or_default() == "true";

    if !ci {
        std::fs::create_dir_all("src/generated").unwrap();

        prost_build::Config::new()
            .out_dir("src/generated")
            .compile_protos(&["proto/protocol.proto"], &["proto/"])?;
    }

    Ok(())
}
