#![cfg(feature = "gui")]

use eframe::egui;
use khzip::{create_archive, ArchiveFormat, CompressionMode, CreateOptions, CustomCompression};
use std::path::PathBuf;

struct KhzipApp {
    inputs: Vec<PathBuf>,
    recipients: Vec<PathBuf>,
    output: String,
    format: ArchiveFormat,
    mode: CompressionMode,
    password: String,
    status: String,
}

impl Default for KhzipApp {
    fn default() -> Self {
        Self {
            inputs: std::env::args_os()
                .skip(1)
                .map(PathBuf::from)
                .filter(|path| path.exists())
                .collect(),
            recipients: Vec::new(),
            output: String::new(),
            format: ArchiveFormat::Khz,
            mode: CompressionMode::Balanced,
            password: String::new(),
            status: "Add files or a folder to begin.".to_string(),
        }
    }
}

impl eframe::App for KhzipApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading(".khzip");
            ui.label("Private, verifiable archives for local storage and untrusted clouds");
            ui.add_space(8.0);

            ui.group(|ui| {
                ui.strong("1. Content");
                ui.horizontal(|ui| {
                    if ui.button("Add files").clicked() {
                        if let Some(files) = rfd::FileDialog::new().pick_files() {
                            self.inputs.extend(files);
                        }
                    }
                    if ui.button("Add folder").clicked() {
                        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                            self.inputs.push(folder);
                        }
                    }
                    if ui.button("Clear").clicked() {
                        self.inputs.clear();
                    }
                });
                egui::ScrollArea::vertical()
                    .max_height(130.0)
                    .show(ui, |ui| {
                        if self.inputs.is_empty() {
                            ui.weak("No content selected");
                        }
                        for input in &self.inputs {
                            ui.label(input.display().to_string());
                        }
                    });
            });

            ui.add_space(8.0);
            ui.group(|ui| {
                ui.strong("2. Archive policy");
                egui::ComboBox::from_label("Format")
                    .selected_text(format!(".{}", self.format))
                    .show_ui(ui, |ui| {
                        for format in [
                            ArchiveFormat::Khz,
                            ArchiveFormat::Khpak,
                            ArchiveFormat::Khx,
                            ArchiveFormat::Khaz,
                            ArchiveFormat::Khcz,
                        ] {
                            ui.selectable_value(
                                &mut self.format,
                                format,
                                format!(".{}", format),
                            );
                        }
                    });
                egui::ComboBox::from_label("Compression")
                    .selected_text(format!("{:?}", self.mode))
                    .show_ui(ui, |ui| {
                        for mode in [
                            CompressionMode::Fast,
                            CompressionMode::Balanced,
                            CompressionMode::Extreme,
                            CompressionMode::Custom,
                        ] {
                            ui.selectable_value(&mut self.mode, mode, format!("{:?}", mode));
                        }
                    });
                ui.horizontal(|ui| {
                    ui.label("Output");
                    ui.text_edit_singleline(&mut self.output);
                    if ui.button("Browse").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .set_file_name(format!("archive.{}", self.format))
                            .save_file()
                        {
                            self.output = path.display().to_string();
                        }
                    }
                });
            });

            ui.add_space(8.0);
            ui.group(|ui| {
                ui.strong("3. Access");
                if self.format.allows_password() {
                    ui.horizontal(|ui| {
                        ui.label("Password");
                        ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Add recipient key").clicked() {
                            if let Some(files) = rfd::FileDialog::new()
                                .add_filter(".khzip public key", &["khpub", "json"])
                                .pick_files()
                            {
                                self.recipients.extend(files);
                            }
                        }
                        if ui.button("Clear recipients").clicked() {
                            self.recipients.clear();
                        }
                    });
                    for recipient in &self.recipients {
                        ui.label(format!("Recipient: {}", recipient.display()));
                    }
                    if self.password.is_empty() && self.recipients.is_empty() {
                        ui.weak("No encryption selected. Add a password or recipient key.");
                    }
                } else if self.format == ArchiveFormat::Khcz {
                    ui.label(
                        "Uses this device's local key. Back it up separately; loss is unrecoverable.",
                    );
                } else {
                    ui.label("This format is intentionally unencrypted.");
                }
            });

            ui.add_space(10.0);
            if ui
                .add_enabled(
                    !self.inputs.is_empty() && !self.output.trim().is_empty(),
                    egui::Button::new("Create archive"),
                )
                .clicked()
            {
                self.status = match self.create() {
                    Ok(text) => text,
                    Err(error) => format!("Error: {error:#}"),
                };
            }
            ui.separator();
            ui.label(&self.status);
        });
    }
}

impl KhzipApp {
    fn create(&self) -> anyhow::Result<String> {
        let password = if self.format.allows_password() && !self.password.is_empty() {
            Some(self.password.clone())
        } else {
            None
        };
        let summary = create_archive(&CreateOptions {
            inputs: self.inputs.clone(),
            output: PathBuf::from(&self.output),
            format: self.format,
            mode: self.mode,
            password,
            recipients: self.recipients.clone(),
            custom: CustomCompression::default(),
            split_size: 100 * 1024 * 1024,
        })?;
        Ok(format!(
            "Created {} files in {} unique chunks.",
            summary.files, summary.chunks
        ))
    }
}

fn main() -> eframe::Result {
    eframe::run_native(
        ".khzip",
        eframe::NativeOptions::default(),
        Box::new(|_| Ok(Box::new(KhzipApp::default()))),
    )
}
