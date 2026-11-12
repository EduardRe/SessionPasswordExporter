#[path = "src/ui/icon.rs"]
mod icon;

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=src/ui/icon.rs");

    if env::var("CARGO_CFG_TARGET_OS").ok().as_deref() != Some("windows") {
        return Ok(());
    }

    let app_icon = icon::app_icon();
    let icon_path = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?)
        .join("session-password-exporter.ico");
    fs::write(&icon_path, encode_ico(&app_icon))?;

    let output_directory = icon_path.parent().ok_or("OUT_DIR has no parent")?;
    let rc_path = output_directory.join("app_icon.rc");
    let resource_path = output_directory.join("app_icon.res");
    fs::write(&rc_path, "1 ICON \"session-password-exporter.ico\"\r\n")?;

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")?;
    let resource_compiler = find_resource_compiler(&target_arch)?;
    let output = Command::new(&resource_compiler)
        .current_dir(output_directory)
        .arg("/nologo")
        .arg("/fo")
        .arg(&resource_path)
        .arg(&rc_path)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "Windows resource compiler failed ({}): {}",
            resource_compiler.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }

    println!(
        "cargo:rustc-link-arg-bin=session-password-exporter={}",
        resource_path.display()
    );

    Ok(())
}

fn find_resource_compiler(target_arch: &str) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = env::var_os("RC") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }

    if let Ok(output) = Command::new("where.exe").arg("rc.exe").output()
        && output.status.success()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let path = PathBuf::from(line.trim());
            if path.is_file() {
                return Ok(path);
            }
        }
    }

    let sdk_arch = match target_arch {
        "x86_64" => "x64",
        "x86" => "x86",
        "aarch64" => "arm64",
        other => return Err(format!("Unsupported Windows target architecture: {other}").into()),
    };
    let mut sdk_bin_directories = Vec::new();
    if let Some(sdk_dir) = env::var_os("WindowsSdkDir") {
        sdk_bin_directories.push(PathBuf::from(sdk_dir).join("bin"));
    }
    for variable in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(program_files) = env::var_os(variable) {
            sdk_bin_directories.push(PathBuf::from(program_files).join("Windows Kits/10/bin"));
        }
    }

    for sdk_bin in sdk_bin_directories {
        if let Some(path) = find_versioned_resource_compiler(&sdk_bin, sdk_arch) {
            return Ok(path);
        }
    }

    Err("Windows SDK rc.exe was not found. Install the Windows 10/11 SDK or set the RC environment variable.".into())
}

fn find_versioned_resource_compiler(sdk_bin: &Path, sdk_arch: &str) -> Option<PathBuf> {
    let direct_path = sdk_bin.join(sdk_arch).join("rc.exe");
    if direct_path.is_file() {
        return Some(direct_path);
    }

    let mut version_directories = fs::read_dir(sdk_bin)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    version_directories.sort_by_key(|path| version_key(path));
    version_directories.reverse();

    version_directories
        .into_iter()
        .map(|directory| directory.join(sdk_arch).join("rc.exe"))
        .find(|path| path.is_file())
}

fn version_key(path: &Path) -> Vec<u64> {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

fn encode_ico(icon: &icon::RgbaIcon) -> Vec<u8> {
    let width = icon.width as usize;
    let height = icon.height as usize;
    let xor_stride = width * 4;
    let mask_stride = width.div_ceil(32) * 4;
    let xor_size = xor_stride * height;
    let mask_size = mask_stride * height;
    let image_size = 40 + xor_size + mask_size;
    let image_offset = 6 + 16;

    let mut ico = Vec::with_capacity(image_offset + image_size);
    push_u16(&mut ico, 0); // reserved
    push_u16(&mut ico, 1); // icon resource
    push_u16(&mut ico, 1); // image count

    ico.push(if width == 256 { 0 } else { width as u8 });
    ico.push(if height == 256 { 0 } else { height as u8 });
    ico.push(0); // default color count
    ico.push(0); // reserved
    push_u16(&mut ico, 1); // color planes
    push_u16(&mut ico, 32); // bits per pixel
    push_u32(&mut ico, image_size as u32);
    push_u32(&mut ico, image_offset as u32);

    push_u32(&mut ico, 40); // BITMAPINFOHEADER size
    push_u32(&mut ico, width as u32);
    push_u32(&mut ico, (height * 2) as u32); // color bitmap plus transparency mask
    push_u16(&mut ico, 1);
    push_u16(&mut ico, 32);
    push_u32(&mut ico, 0); // BI_RGB
    push_u32(&mut ico, (xor_size + mask_size) as u32);
    push_u32(&mut ico, 0); // horizontal pixels per meter
    push_u32(&mut ico, 0); // vertical pixels per meter
    push_u32(&mut ico, 0); // colors used
    push_u32(&mut ico, 0); // important colors

    for y in (0..height).rev() {
        for x in 0..width {
            let offset = (y * width + x) * 4;
            ico.extend([
                icon.rgba[offset + 2],
                icon.rgba[offset + 1],
                icon.rgba[offset],
                icon.rgba[offset + 3],
            ]);
        }
    }

    for y in (0..height).rev() {
        let mut mask_row = vec![0_u8; mask_stride];
        for x in 0..width {
            let alpha_offset = (y * width + x) * 4 + 3;
            if icon.rgba[alpha_offset] < 128 {
                mask_row[x / 8] |= 1 << (7 - x % 8);
            }
        }
        ico.extend(mask_row);
    }

    ico
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend(value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend(value.to_le_bytes());
}
