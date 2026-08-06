use khzip::{
    create_archive, extract_archive, list_archive, verify_archive, ArchiveFormat, CompressionMode,
    CreateOptions, CustomCompression, UnlockOptions,
};
use std::fs;
use tempfile::tempdir;

#[test]
fn encrypted_round_trip_and_wrong_password_rejection() {
    let root = tempdir().unwrap();
    let input = root.path().join("input");
    fs::create_dir(&input).unwrap();
    fs::write(
        input.join("hello.txt"),
        "hello secure world\n".repeat(10_000),
    )
    .unwrap();
    fs::write(
        input.join("copy.txt"),
        "hello secure world\n".repeat(10_000),
    )
    .unwrap();
    let archive = root.path().join("backup.khz");
    let password = "correct horse battery staple";

    let summary = create_archive(&CreateOptions {
        inputs: vec![input.clone()],
        output: archive.clone(),
        format: ArchiveFormat::Khz,
        mode: CompressionMode::Balanced,
        password: Some(password.to_string()),
        custom: CustomCompression::default(),
        split_size: 1024 * 1024,
    })
    .unwrap();
    assert_eq!(summary.files, 2);
    assert!(summary.unique_bytes < summary.original_bytes);

    let unlock = UnlockOptions {
        password: Some(password.to_string()),
    };
    verify_archive(&archive, &unlock).unwrap();
    assert!(list_archive(
        &archive,
        &UnlockOptions {
            password: Some("wrong password".to_string()),
        }
    )
    .is_err());

    let output = root.path().join("restored");
    extract_archive(&archive, &output, &unlock, false).unwrap();
    assert_eq!(
        fs::read(input.join("hello.txt")).unwrap(),
        fs::read(output.join("input/hello.txt")).unwrap()
    );
}

#[test]
fn split_archive_round_trip() {
    let root = tempdir().unwrap();
    let input = root.path().join("data.bin");
    let bytes: Vec<u8> = (0..2_500_000).map(|index| (index % 251) as u8).collect();
    fs::write(&input, &bytes).unwrap();
    let archive = root.path().join("parts.khx");
    create_archive(&CreateOptions {
        inputs: vec![input],
        output: archive,
        format: ArchiveFormat::Khx,
        mode: CompressionMode::Fast,
        password: None,
        custom: CustomCompression::default(),
        split_size: 1024 * 1024,
    })
    .unwrap();
    let first = root.path().join("parts.khx.001");
    assert!(first.exists());
    verify_archive(&first, &UnlockOptions::default()).unwrap();
}

#[test]
fn khpak_rejects_password() {
    let root = tempdir().unwrap();
    let input = root.path().join("file.txt");
    fs::write(&input, "data").unwrap();
    let result = create_archive(&CreateOptions {
        inputs: vec![input],
        output: root.path().join("assets.khpak"),
        format: ArchiveFormat::Khpak,
        mode: CompressionMode::Fast,
        password: Some("not allowed password".to_string()),
        custom: CustomCompression::default(),
        split_size: 1024 * 1024,
    });
    assert!(result.is_err());
}
