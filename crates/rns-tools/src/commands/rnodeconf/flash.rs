//! Firmware flasher command planning.

use std::path::{Path, PathBuf};

use super::model;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashContext {
    pub python: String,
    pub port: String,
    pub baud_flash: String,
    pub update_dir: PathBuf,
    pub extracted_dir: PathBuf,
    pub selected_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashPlan {
    pub program: String,
    pub args: Vec<String>,
}

impl FlashPlan {
    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(self.args.len() + 1);
        argv.push(self.program.clone());
        argv.extend(self.args.clone());
        argv
    }
}

pub fn plan_unzip(update_dir: &Path, version: &str, fw_filename: &str) -> FlashPlan {
    let archive = update_dir.join(version).join(fw_filename);
    FlashPlan {
        program: "unzip".to_string(),
        args: vec![
            "-o".to_string(),
            path_string(&archive),
            "-d".to_string(),
            path_string(&update_dir.join(version)),
        ],
    }
}

pub fn plan_flasher(platform: u8, fw_filename: &str, ctx: &FlashContext) -> Option<FlashPlan> {
    match platform {
        model::PLATFORM_AVR => plan_avr(fw_filename, ctx),
        model::PLATFORM_ESP32 => plan_esp32(fw_filename, ctx),
        model::PLATFORM_NRF52 => Some(plan_nrf52(fw_filename, ctx)),
        _ => None,
    }
}

fn plan_avr(fw_filename: &str, ctx: &FlashContext) -> Option<FlashPlan> {
    let mut args = vec!["-P".to_string(), ctx.port.clone()];
    match fw_filename {
        "rnode_firmware.hex" => {
            args.extend([
                "-p".to_string(),
                "m1284p".to_string(),
                "-c".to_string(),
                "arduino".to_string(),
                "-b".to_string(),
                "115200".to_string(),
                "-U".to_string(),
                format!(
                    "flash:w:{}:i",
                    path_string(&ctx.update_dir.join(&ctx.selected_version).join(fw_filename))
                ),
            ]);
        }
        "rnode_firmware_m2560.hex" => {
            args.extend([
                "-p".to_string(),
                "atmega2560".to_string(),
                "-c".to_string(),
                "wiring".to_string(),
                "-D".to_string(),
                "-b".to_string(),
                "115200".to_string(),
                "-U".to_string(),
                format!(
                    "flash:w:{}",
                    path_string(&ctx.update_dir.join(&ctx.selected_version).join(fw_filename))
                ),
            ]);
        }
        _ => return None,
    }
    Some(FlashPlan {
        program: "avrdude".to_string(),
        args,
    })
}

fn plan_nrf52(fw_filename: &str, ctx: &FlashContext) -> FlashPlan {
    FlashPlan {
        program: "adafruit-nrfutil".to_string(),
        args: vec![
            "dfu".to_string(),
            "serial".to_string(),
            "--package".to_string(),
            path_string(&ctx.update_dir.join(&ctx.selected_version).join(fw_filename)),
            "-p".to_string(),
            ctx.port.clone(),
            "-b".to_string(),
            "115200".to_string(),
            "-t".to_string(),
            "1200".to_string(),
        ],
    }
}

fn plan_esp32(fw_filename: &str, ctx: &FlashContext) -> Option<FlashPlan> {
    if fw_filename == "extracted_rnode_firmware.zip" {
        return Some(FlashPlan {
            program: ctx.python.clone(),
            args: esp32_args(
                &ctx.update_dir
                    .join(&ctx.selected_version)
                    .join("esptool.py"),
                "esp32",
                &ctx.port,
                &ctx.baud_flash,
                "4MB",
                &[
                    (
                        "0x1000",
                        ctx.extracted_dir
                            .join("extracted_rnode_firmware.bootloader"),
                    ),
                    (
                        "0xe000",
                        ctx.extracted_dir.join("extracted_rnode_firmware.boot_app0"),
                    ),
                    (
                        "0x8000",
                        ctx.extracted_dir
                            .join("extracted_rnode_firmware.partitions"),
                    ),
                    (
                        "0x10000",
                        ctx.extracted_dir.join("extracted_rnode_firmware.bin"),
                    ),
                    (
                        "0x210000",
                        ctx.extracted_dir.join("extracted_console_image.bin"),
                    ),
                ],
            ),
        });
    }

    let spec = esp32_spec(fw_filename)?;
    let version_dir = ctx.update_dir.join(&ctx.selected_version);
    let stem = fw_filename.strip_suffix(".zip")?;
    let mut images = vec![
        ("0xe000", version_dir.join(format!("{stem}.boot_app0"))),
        (
            spec.bootloader_offset,
            version_dir.join(format!("{stem}.bootloader")),
        ),
        ("0x10000", version_dir.join(format!("{stem}.bin"))),
    ];
    if spec.include_console || version_at_least(&ctx.selected_version, 1.55) {
        images.push(("0x210000", version_dir.join("console_image.bin")));
    }
    images.push(("0x8000", version_dir.join(format!("{stem}.partitions"))));

    Some(FlashPlan {
        program: ctx.python.clone(),
        args: esp32_args(
            &version_dir.join("esptool.py"),
            spec.chip,
            &ctx.port,
            &ctx.baud_flash,
            spec.flash_size,
            &images,
        ),
    })
}

#[derive(Debug, Clone, Copy)]
struct Esp32Spec {
    chip: &'static str,
    flash_size: &'static str,
    bootloader_offset: &'static str,
    include_console: bool,
}

fn esp32_spec(fw_filename: &str) -> Option<Esp32Spec> {
    let s3 = Esp32Spec {
        chip: "esp32s3",
        flash_size: "4MB",
        bootloader_offset: "0x0",
        include_console: true,
    };
    Some(match fw_filename {
        "rnode_firmware_t3s3.zip"
        | "rnode_firmware_t3s3_sx127x.zip"
        | "rnode_firmware_t3s3_sx1280_pa.zip"
        | "rnode_firmware_tbeam_supreme.zip"
        | "rnode_firmware_tdeck.zip" => s3,
        "rnode_firmware_xiao_esp32s3.zip" => Esp32Spec {
            flash_size: "8MB",
            ..s3
        },
        "rnode_firmware_heltec32v4pa.zip" => Esp32Spec {
            chip: "esp32-s3",
            flash_size: "16MB",
            bootloader_offset: "0x0",
            include_console: true,
        },
        "rnode_firmware_heltec32v3.zip" => Esp32Spec {
            chip: "esp32s3",
            flash_size: "8MB",
            bootloader_offset: "0x0",
            include_console: true,
        },
        "rnode_firmware_tbeam.zip"
        | "rnode_firmware_tbeam_sx1262.zip"
        | "rnode_firmware_lora32v10.zip"
        | "rnode_firmware_lora32v20.zip"
        | "rnode_firmware_lora32v21.zip"
        | "rnode_firmware_lora32v21_tcxo.zip"
        | "rnode_firmware_heltec32v2.zip"
        | "rnode_firmware_featheresp32.zip"
        | "rnode_firmware_esp32_generic.zip"
        | "rnode_firmware_ng20.zip"
        | "rnode_firmware_ng21.zip" => Esp32Spec {
            chip: "esp32",
            flash_size: "4MB",
            bootloader_offset: "0x1000",
            include_console: false,
        },
        _ => return None,
    })
}

fn esp32_args(
    flasher: &Path,
    chip: &str,
    port: &str,
    baud: &str,
    flash_size: &str,
    images: &[(&str, PathBuf)],
) -> Vec<String> {
    let mut args = vec![
        path_string(flasher),
        "--chip".to_string(),
        chip.to_string(),
        "--port".to_string(),
        port.to_string(),
        "--baud".to_string(),
        baud.to_string(),
        "--before".to_string(),
        "default_reset".to_string(),
        "--after".to_string(),
        "hard_reset".to_string(),
        "write_flash".to_string(),
        "-z".to_string(),
        "--flash_mode".to_string(),
        "dio".to_string(),
        "--flash_freq".to_string(),
        "80m".to_string(),
        "--flash_size".to_string(),
        flash_size.to_string(),
    ];
    for (offset, path) in images {
        args.push((*offset).to_string());
        args.push(path_string(path));
    }
    args
}

fn version_at_least(version: &str, min: f64) -> bool {
    version.parse::<f64>().map(|v| v >= min).unwrap_or(false)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> FlashContext {
        FlashContext {
            python: "python3".to_string(),
            port: "/dev/ttyUSB0".to_string(),
            baud_flash: "921600".to_string(),
            update_dir: PathBuf::from("/cache/update"),
            extracted_dir: PathBuf::from("/cache/extracted"),
            selected_version: "1.74".to_string(),
        }
    }

    fn update_version_file(filename: &str) -> String {
        path_string(&PathBuf::from("/cache/update").join("1.74").join(filename))
    }

    #[test]
    fn avr_plan_matches_upstream_avrdude_shape() {
        let plan = plan_flasher(model::PLATFORM_AVR, "rnode_firmware.hex", &ctx()).unwrap();
        let argv = plan.argv();
        assert_eq!(argv[0], "avrdude");
        assert!(argv.contains(&"m1284p".to_string()));
        let flash_arg = format!("flash:w:{}:i", update_version_file("rnode_firmware.hex"));
        assert!(
            argv.iter().any(|arg| arg == &flash_arg),
            "missing flash argument in {argv:?}"
        );
    }

    #[test]
    fn esp32_s3_plan_uses_full_partition_table() {
        let plan = plan_flasher(model::PLATFORM_ESP32, "rnode_firmware_t3s3.zip", &ctx()).unwrap();
        let argv = plan.argv();
        assert_eq!(argv[0], "python3");
        assert!(argv.contains(&"esp32s3".to_string()));
        assert!(argv.contains(&"0x210000".to_string()));
        let firmware_bin = update_version_file("rnode_firmware_t3s3.bin");
        assert!(
            argv.iter().any(|arg| arg == &firmware_bin),
            "missing firmware image in {argv:?}"
        );
    }

    #[test]
    fn nrf52_plan_never_invokes_hardware_in_tests() {
        let plan =
            plan_flasher(model::PLATFORM_NRF52, "rnode_firmware_rak4631.zip", &ctx()).unwrap();
        assert_eq!(
            plan.argv(),
            vec![
                "adafruit-nrfutil".to_string(),
                "dfu".to_string(),
                "serial".to_string(),
                "--package".to_string(),
                update_version_file("rnode_firmware_rak4631.zip"),
                "-p".to_string(),
                "/dev/ttyUSB0".to_string(),
                "-b".to_string(),
                "115200".to_string(),
                "-t".to_string(),
                "1200".to_string(),
            ]
        );
    }
}
