use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn find_rc_exe(target_arch: &str) -> Option<PathBuf> {
    if let Ok(rc) = env::var("RC") {
        let p = PathBuf::from(rc);
        if p.is_file() {
            return Some(p);
        }
    }
    if Command::new("rc.exe").arg("/?").output().is_ok() {
        return Some(PathBuf::from("rc.exe"));
    }

    let sdk_arch = match target_arch {
        "aarch64" => "arm64",
        "x86" => "x86",
        _ => "x64",
    };

    for root in [
        r"C:\Program Files (x86)\Windows Kits\10\bin",
        r"C:\Program Files\Windows Kits\10\bin",
    ] {
        let root_path = Path::new(root);
        let Ok(entries) = std::fs::read_dir(root_path) else {
            continue;
        };
        let mut versions: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        versions.sort();
        versions.reverse();
        for ver in versions {
            let candidate = ver.join(sdk_arch).join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn main() {
    println!("cargo:rerun-if-changed=windows/app.manifest");
    println!("cargo:rerun-if-changed=windows/sshcast.rc");
    println!("cargo:rerun-if-changed=windows/sshcast.ico");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target_os == "windows" && target_env == "msvc" {
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let manifest_path = manifest_dir.join("windows").join("app.manifest");
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
            manifest_path.display()
        );

        let rc_path = manifest_dir.join("windows").join("sshcast.rc");
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let res_path = out_dir.join("sshcast.res");

        if let Some(rc_exe) = find_rc_exe(&target_arch) {
            let status = Command::new(&rc_exe)
                .arg("/nologo")
                .arg(format!("/fo{}", res_path.display()))
                .arg(&rc_path)
                .status();
            match status {
                Ok(st) if st.success() && res_path.is_file() => {
                    println!("cargo:rustc-link-arg-bins={}", res_path.display());
                }
                Ok(st) => {
                    println!("cargo:warning=rc.exe exited with {st}; skipping Windows icon resource");
                }
                Err(e) => {
                    println!("cargo:warning=failed to run rc.exe ({e}); skipping Windows icon resource");
                }
            }
        } else {
            println!("cargo:warning=rc.exe not found; skipping Windows icon resource");
        }
    }
}
