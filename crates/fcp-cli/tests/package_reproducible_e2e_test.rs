//! E2E tests for reproducible connector builds (bd-6phb).
//!
//! Validates that building the same connector twice produces identical artifacts,
//! ensuring deterministic builds per the FCP2 reproducibility requirements.
//!
//! # Test Scenarios
//!
//! - Build the same connector crate twice; verify identical SHA-256 hashes
//! - Verify packaged artifact contains expected metadata
//!
//! # Logging
//!
//! All tests emit structured JSONL per `docs/STANDARD_Testing_Logging.md`.

use assert_cmd::cargo::cargo_bin_cmd;
use chrono::Utc;
use fcp_testkit::LogCapture;
use serde_json::Value;
use std::fs;
use std::time::Instant;
use tempfile::TempDir;

/// Create a minimal test connector crate for deterministic builds.
fn create_test_connector(path: &std::path::Path) {
    fs::create_dir_all(path.join("src")).expect("create src dir");

    // Cargo.toml with fixed metadata (no timestamps or dynamic values)
    let cargo_toml = r#"[package]
name = "fcp_reproducible_test"
version = "1.0.0"
edition = "2024"

[profile.release]
# Deterministic build settings
lto = true
codegen-units = 1
strip = true
"#;
    fs::write(path.join("Cargo.toml"), cargo_toml).expect("write Cargo.toml");

    // Minimal main.rs with no dynamic content
    let main_rs = r"//! Minimal connector for reproducibility testing.
fn main() {
    // Intentionally empty - just a build artifact test
}
";
    fs::write(path.join("src/main.rs"), main_rs).expect("write main.rs");

    // Fixed manifest (no timestamps)
    let manifest = r#"[connector]
id = "fcp.test:reproducible:v1"
version = "1.0.0"
"#;
    fs::write(path.join("manifest.toml"), manifest).expect("write manifest.toml");
}

/// Run `fcp package` and return the parsed output JSON.
fn run_package(crate_path: &std::path::Path, output_dir: &std::path::Path) -> Value {
    let mut cmd = cargo_bin_cmd!("fcp");
    let output = cmd
        .args([
            "package",
            "--path",
            crate_path.to_str().expect("crate path"),
            "--output",
            output_dir.to_str().expect("output path"),
            "--format",
            "json",
            "--skip-sbom", // Skip SBOM to isolate binary reproducibility
        ])
        .env("CARGO_INCREMENTAL", "0")
        .env("RUSTFLAGS", "-C debuginfo=0")
        .env("SOURCE_DATE_EPOCH", "1700000000") // Fixed timestamp for embedded metadata
        .output()
        .expect("run fcp package");

    assert!(
        output.status.success(),
        "fcp package failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    serde_json::from_str(&stdout).expect("parse package JSON output")
}

/// Extract binary SHA-256 from package output.
fn extract_sha256(output: &Value) -> String {
    output
        .get("binary_sha256")
        .and_then(|v| v.as_str())
        .expect("binary_sha256 in output")
        .to_string()
}

mod e2e_reproducible {
    use super::*;

    /// Build the same connector twice and verify identical hashes.
    #[test]
    fn reproducible_build_produces_identical_hash() {
        let capture = LogCapture::new();
        let correlation_id = format!(
            "repro-{}-{}",
            std::process::id(),
            Utc::now().timestamp_millis()
        );
        let start = Instant::now();

        // Setup: Create test connector in temp directory
        let temp = TempDir::new().expect("tempdir");
        let crate_path = temp.path().join("connector");
        create_test_connector(&crate_path);

        // Build #1
        let output_dir_1 = temp.path().join("out1");
        fs::create_dir_all(&output_dir_1).expect("create output dir 1");
        let result_1 = run_package(&crate_path, &output_dir_1);
        let hash_1 = extract_sha256(&result_1);

        // Clean cargo target to force full rebuild
        let target_dir = crate_path.join("target");
        if target_dir.exists() {
            fs::remove_dir_all(&target_dir).expect("clean target dir");
        }

        // Build #2
        let output_dir_2 = temp.path().join("out2");
        fs::create_dir_all(&output_dir_2).expect("create output dir 2");
        let result_2 = run_package(&crate_path, &output_dir_2);
        let hash_2 = extract_sha256(&result_2);

        // Verify: Hashes must be identical
        let hashes_match = hash_1 == hash_2;
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        capture.push_line(
            &serde_json::json!({
                "timestamp": Utc::now().to_rfc3339(),
                "level": if hashes_match { "info" } else { "error" },
                "test_name": "reproducible_build_produces_identical_hash",
                "module": "fcp-cli::package::e2e",
                "phase": "verify",
                "correlation_id": &correlation_id,
                "result": if hashes_match { "pass" } else { "fail" },
                "duration_ms": duration_ms,
                "assertions": { "passed": i32::from(hashes_match), "failed": i32::from(!hashes_match) },
                "details": {
                    "hash_1": &hash_1,
                    "hash_2": &hash_2,
                    "identical": hashes_match
                }
            })
            .to_string(),
        );

        capture.validate_jsonl().expect("JSONL schema validation");

        assert_eq!(
            hash_1, hash_2,
            "Reproducible build failed: build #1 hash ({hash_1}) != build #2 hash ({hash_2})"
        );
    }

    /// Verify packaged artifact contains valid build metadata.
    #[test]
    fn packaged_artifact_has_valid_metadata() {
        let capture = LogCapture::new();
        let correlation_id = format!(
            "meta-{}-{}",
            std::process::id(),
            Utc::now().timestamp_millis()
        );
        let start = Instant::now();

        let temp = TempDir::new().expect("tempdir");
        let crate_path = temp.path().join("connector");
        create_test_connector(&crate_path);

        let output_dir = temp.path().join("out");
        fs::create_dir_all(&output_dir).expect("create output dir");

        let result = run_package(&crate_path, &output_dir);

        // Verify package output structure
        let binary_sha256 = result
            .get("binary_sha256")
            .and_then(|v| v.as_str())
            .expect("binary_sha256");
        assert_eq!(binary_sha256.len(), 64, "SHA-256 should be 64 hex chars");

        let connector_id = result
            .get("connector_id")
            .and_then(|v| v.as_str())
            .expect("connector_id");
        assert_eq!(connector_id, "fcp.test:reproducible:v1");

        let version = result
            .get("version")
            .and_then(|v| v.as_str())
            .expect("version");
        assert_eq!(version, "1.0.0");

        // Verify build metadata file
        let metadata_path = result
            .get("build_metadata_path")
            .and_then(|v| v.as_str())
            .expect("build_metadata_path");
        let metadata: Value =
            serde_json::from_str(&fs::read_to_string(metadata_path).expect("read build metadata"))
                .expect("parse build metadata");

        let rust_version = metadata
            .get("rust_version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        // rust_version can be "unknown" if rustc isn't available, but should exist
        assert!(
            metadata.get("rust_version").is_some(),
            "rust_version key should exist"
        );

        let _cargo_version = metadata
            .get("cargo_version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        assert!(
            metadata.get("cargo_version").is_some(),
            "cargo_version key should exist"
        );

        let target_triple = metadata
            .get("target_triple")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        assert!(
            metadata.get("target_triple").is_some(),
            "target_triple key should exist"
        );

        let profile = metadata
            .get("profile")
            .and_then(|v| v.as_str())
            .expect("profile");
        assert_eq!(profile, "release", "default profile should be release");

        // Verify manifest round-trip
        let manifest_path = result
            .get("manifest_path")
            .and_then(|v| v.as_str())
            .expect("manifest_path");
        let manifest_content = fs::read_to_string(manifest_path).expect("read manifest");
        assert!(
            manifest_content.contains("fcp.test:reproducible:v1"),
            "manifest should contain connector ID"
        );

        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        capture.push_line(
            &serde_json::json!({
                "timestamp": Utc::now().to_rfc3339(),
                "level": "info",
                "test_name": "packaged_artifact_has_valid_metadata",
                "module": "fcp-cli::package::e2e",
                "phase": "verify",
                "correlation_id": &correlation_id,
                "result": "pass",
                "duration_ms": duration_ms,
                "assertions": { "passed": 8, "failed": 0 },
                "details": {
                    "connector_id": connector_id,
                    "version": version,
                    "binary_sha256": binary_sha256,
                    "rust_version": rust_version,
                    "target_triple": target_triple
                }
            })
            .to_string(),
        );

        capture.validate_jsonl().expect("JSONL schema validation");
    }

    /// Verify binary file actually exists and has nonzero size.
    #[test]
    fn packaged_binary_exists_and_has_content() {
        let capture = LogCapture::new();
        let correlation_id = format!(
            "bin-{}-{}",
            std::process::id(),
            Utc::now().timestamp_millis()
        );
        let start = Instant::now();

        let temp = TempDir::new().expect("tempdir");
        let crate_path = temp.path().join("connector");
        create_test_connector(&crate_path);

        let output_dir = temp.path().join("out");
        fs::create_dir_all(&output_dir).expect("create output dir");

        let result = run_package(&crate_path, &output_dir);

        let binary_path = result
            .get("binary_path")
            .and_then(|v| v.as_str())
            .expect("binary_path");

        // Verify binary exists
        let binary_file = std::path::Path::new(binary_path);
        assert!(
            binary_file.exists(),
            "Binary file should exist at {binary_path}"
        );

        // Verify binary has content
        let metadata = fs::metadata(binary_file).expect("binary metadata");
        let file_size = metadata.len();
        assert!(file_size > 0, "Binary should have nonzero size");

        // Verify binary is actually executable (on Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = metadata.permissions();
            // Check if any execute bit is set (user, group, or other)
            let is_executable = permissions.mode() & 0o111 != 0;
            assert!(is_executable, "Binary should be executable");
        }

        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        capture.push_line(
            &serde_json::json!({
                "timestamp": Utc::now().to_rfc3339(),
                "level": "info",
                "test_name": "packaged_binary_exists_and_has_content",
                "module": "fcp-cli::package::e2e",
                "phase": "verify",
                "correlation_id": &correlation_id,
                "result": "pass",
                "duration_ms": duration_ms,
                "assertions": { "passed": 3, "failed": 0 },
                "details": {
                    "binary_path": binary_path,
                    "file_size_bytes": file_size
                }
            })
            .to_string(),
        );

        capture.validate_jsonl().expect("JSONL schema validation");
    }
}
