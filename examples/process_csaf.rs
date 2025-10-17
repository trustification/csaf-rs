use anyhow::bail;
use csaf::Csaf;
use cvss;
use std::ffi::OsStr;
use std::path::Path;
use std::process::ExitCode;
use walkdir::WalkDir;

fn main() -> anyhow::Result<ExitCode> {
    let mut files = Vec::new();
    let walker = WalkDir::new("tests")
        .follow_links(true)
        .contents_first(true);

    for entry in walker {
        let entry = entry?;

        if !entry.file_type().is_file() {
            continue;
        }

        if entry.path().extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }

        files.push(entry.into_path());
    }

    for file in files {
        if let Err(err) = process(&file) {
            eprintln!("Failed to process {}: {}", file.display(), err);
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn process(path: &Path) -> anyhow::Result<()> {
    let content = std::fs::read(path)?;
    let csaf: Csaf = match serde_json::from_slice(&content) {
        Ok(csaf) => csaf,
        Err(err) => {
            bail!("Failed to parse {}: {}", path.display(), err);
        }
    };

    println!("Processing CSAF document: {}", csaf.document.title);

    if let Some(vulnerabilities) = csaf.vulnerabilities {
        for vulnerability in vulnerabilities {
            if let Some(scores) = vulnerability.scores {
                for score in scores {
                    if let Some(cvss_v3) = score.cvss_v3 {
                        let cvss: cvss::Cvss = serde_json::from_value(cvss_v3.clone())?;
                        println!("  CVSSv3 Vector: {}", cvss.to_string());
                    }
                }
            }
        }
    }

    Ok(())
}
