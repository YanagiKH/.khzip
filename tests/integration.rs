use khzip::{
    create_archive, extract_archive, generate_keypair, inspect_key, list_archive, verify_archive,
    ArchiveFormat, CompressionMode, CreateOptions, CustomCompression, KeyAlgorithm, UnlockOptions,
};
use std::{fs, path::Path};
use tempfile::tempdir;

fn create_options(input: &Path, output: &Path) -> CreateOptions {
    CreateOptions {
        inputs: vec![input.to_path_buf()],
        output: output.to_path_buf(),
        format: ArchiveFormat::Khz,
        mode: CompressionMode::Balanced,
        password: None,
        recipients: Vec::new(),
        custom: CustomCompression::default(),
        split_size: 1024 * 1024,
    }
}

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

    let mut options = create_options(&input, &archive);
    options.password = Some(password.to_string());
    let summary = create_archive(&options).unwrap();
    assert_eq!(summary.files, 2);
    assert!(summary.unique_bytes < summary.original_bytes);

    let unlock = UnlockOptions {
        password: Some(password.to_string()),
        identities: Vec::new(),
    };
    verify_archive(&archive, &unlock).unwrap();
    assert!(list_archive(
        &archive,
        &UnlockOptions {
            password: Some("wrong password".to_string()),
            identities: Vec::new(),
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
    let mut options = create_options(&input, &archive);
    options.format = ArchiveFormat::Khx;
    options.mode = CompressionMode::Fast;
    create_archive(&options).unwrap();
    let first = root.path().join("parts.khx.001");
    assert!(first.exists());
    verify_archive(&first, &UnlockOptions::default()).unwrap();
}

#[test]
fn khpak_rejects_password_and_recipients() {
    let root = tempdir().unwrap();
    let input = root.path().join("file.txt");
    fs::write(&input, "data").unwrap();
    let mut options = create_options(&input, &root.path().join("assets.khpak"));
    options.format = ArchiveFormat::Khpak;
    options.password = Some("not allowed password".to_string());
    assert!(create_archive(&options).is_err());
}

#[test]
fn encrypted_record_headers_do_not_expose_chunk_metadata() {
    let root = tempdir().unwrap();
    let input = root.path().join("private.txt");
    let content = b"confidential record metadata".repeat(2048);
    fs::write(&input, &content).unwrap();
    let archive = root.path().join("private.khz");

    let mut options = create_options(&input, &archive);
    options.password = Some("correct horse battery staple".to_string());
    create_archive(&options).unwrap();

    let bytes = fs::read(archive).unwrap();
    let chunk_id = blake3::hash(&content);
    assert!(!bytes
        .windows(32)
        .any(|window| window == chunk_id.as_bytes()));
    assert_eq!(&bytes[72..88], &[0_u8; 16]);
    let key_slots_len = u64::from_le_bytes(bytes[88..96].try_into().unwrap()) as usize;
    assert!(key_slots_len > 0);
    let first_record = 128 + key_slots_len;
    assert_eq!(bytes[first_record + 5], 0);
    assert_eq!(&bytes[first_record + 16..first_record + 24], &[0_u8; 8]);
    assert_eq!(&bytes[first_record + 32..first_record + 64], &[0_u8; 32]);
}

#[test]
fn recipient_algorithms_round_trip() {
    for algorithm in [
        KeyAlgorithm::X25519,
        KeyAlgorithm::MlKem768,
        KeyAlgorithm::XWing,
    ] {
        let root = tempdir().unwrap();
        let input = root.path().join("payload.txt");
        fs::write(&input, format!("recipient test for {algorithm}\n").repeat(2048)).unwrap();
        let public = root.path().join("recipient.khpub");
        let secret = root.path().join("recipient.khsec");
        let info = generate_keypair(algorithm, &public, &secret, false).unwrap();
        assert_eq!(info.algorithm, algorithm);
        assert!(inspect_key(&public).unwrap().has_secret == false);
        assert!(inspect_key(&secret).unwrap().has_secret);

        let archive = root.path().join("recipient.khz");
        let mut options = create_options(&input, &archive);
        options.recipients.push(public);
        create_archive(&options).unwrap();
        verify_archive(
            &archive,
            &UnlockOptions {
                password: None,
                identities: vec![secret],
            },
        )
        .unwrap();
    }
}

#[test]
fn password_and_multiple_recipients_can_coexist() {
    let root = tempdir().unwrap();
    let input = root.path().join("payload.txt");
    fs::write(&input, "multi recipient data".repeat(4096)).unwrap();

    let public_a = root.path().join("a.khpub");
    let secret_a = root.path().join("a.khsec");
    generate_keypair(KeyAlgorithm::X25519, &public_a, &secret_a, false).unwrap();
    let public_b = root.path().join("b.khpub");
    let secret_b = root.path().join("b.khsec");
    generate_keypair(KeyAlgorithm::XWing, &public_b, &secret_b, false).unwrap();

    let archive = root.path().join("shared.khaz");
    let mut options = create_options(&input, &archive);
    options.format = ArchiveFormat::Khaz;
    options.password = Some("correct horse battery staple".to_string());
    options.recipients = vec![public_a, public_b];
    create_archive(&options).unwrap();

    verify_archive(
        &archive,
        &UnlockOptions {
            password: None,
            identities: vec![secret_b],
        },
    )
    .unwrap();
    verify_archive(
        &archive,
        &UnlockOptions {
            password: Some("correct horse battery staple".to_string()),
            identities: Vec::new(),
        },
    )
    .unwrap();

    let wrong_public = root.path().join("wrong.khpub");
    let wrong_secret = root.path().join("wrong.khsec");
    generate_keypair(
        KeyAlgorithm::MlKem768,
        &wrong_public,
        &wrong_secret,
        false,
    )
    .unwrap();
    assert!(verify_archive(
        &archive,
        &UnlockOptions {
            password: None,
            identities: vec![wrong_secret],
        }
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn rejects_top_level_symbolic_links() {
    use std::os::unix::fs::symlink;

    let root = tempdir().unwrap();
    let target = root.path().join("target.txt");
    let link = root.path().join("link.txt");
    fs::write(&target, "private").unwrap();
    symlink(&target, &link).unwrap();

    let result = create_archive(&create_options(&link, &root.path().join("archive.khz")));
    assert!(result.is_err());
}
