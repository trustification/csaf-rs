#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

#[cfg(feature = "rustsec-interop")]
pub mod rustsec {
    use std::convert::TryInto;

    use crate::{
        definitions::{
            Branch, BranchCategory, BranchesT, FullProductName, Note, NoteCategory, ProductIdT,
            ProductIdentificationHelper, Reference,
        },
        document::{
            Category, CsafVersion, Document, Generator, Publisher, PublisherCategory, Revision,
            Status, Tracking,
        },
        product_tree::ProductTree,
        vulnerability::{
            ProductStatus, Remediation, RemediationCategory, Score, Vulnerability, VulnerabilityId,
        },
        Csaf,
    };
    use chrono::{TimeZone, Utc};
    use packageurl::PackageUrl;
    use rustsec::{advisory::Versions, registry::IndexPackage, Advisory};
    use url::Url;

    // ASSUMPTIONS:
    // There is no 'history' in RUSTSEC advisories, so current advisory IS initial advisory
    // TODO: Should insert two revisions in the case where withdrawn in set
    //
    // Each RUSTSEC advisory applies to only one 'product' - in this case crate, referred to as Advisory.package

    /// Provides a conversion from a [rustsec::Advisory] to a `Csaf` implementing the [VEX profile](https://github.com/oasis-tcs/csaf/blob/master/csaf_2.0/prose/csaf-v2-editor-draft.md#45-profile-5-vex)
    ///
    /// Currently functioning and passes validation as a CSAF. Is not strictly valid VEX. VEX requires that each `known_not_affected` product
    /// have an impact statement listed as a [Threat](crate::vulnerability::Threat) with [ThreatCategory](crate::vulnerability::ThreatCategory) `Impact`.
    /// RustSec does not have any metadata that "contain(s) a description why the vulnerability cannot be exploited".
    impl From<Advisory> for Csaf {
        fn from(input: Advisory) -> Self {
            let advisory_date = input.metadata.date;
            let advisory_date = Utc
                .with_ymd_and_hms(
                    advisory_date.year().try_into().unwrap(),
                    advisory_date.month(),
                    advisory_date.day(),
                    0,
                    0,
                    0,
                )
                .unwrap();

            let branches =
                BranchTracking::extract_branches(input.metadata.package.as_ref(), &input.versions);

            Csaf {
                document: Document {
                    category: Category::Vex,
                    publisher: Publisher {
                        category: PublisherCategory::Coordinator,
                        name: "RUSTSEC".to_string(),
                        namespace: Url::parse("https://rustsec.org/").unwrap(),
                        contact_details: None,
                        issuing_authority: None,
                    },
                    title: input.metadata.title.clone(),
                    tracking: Tracking {
                        current_release_date: advisory_date,
                        id: input.metadata.id.to_string(),
                        initial_release_date: advisory_date,
                        revision_history: vec![Revision {
                            date: advisory_date,
                            number: "1".to_string(),
                            summary: "RUSTSEC Advisory".to_string(),
                            legacy_version: None,
                        }],
                        status: Status::Final,
                        version: "1".to_string(),
                        aliases: if input.metadata.aliases.is_empty() {
                            None
                        } else {
                            Some(
                                input
                                    .metadata
                                    .aliases
                                    .iter()
                                    .map(|id| id.to_string())
                                    .collect(),
                            )
                        },
                        generator: Some(Generator::default()),
                    },
                    csaf_version: CsafVersion::TwoDotZero,
                    acknowledgments: None,
                    aggregate_severity: None,
                    distribution: None,
                    lang: None, // TODO: Understand if RUSTSEC is canonically english
                    notes: None,
                    references: if input.metadata.references.is_empty() {
                        None
                    } else {
                        Some(
                            input
                                .metadata
                                .references
                                .iter()
                                .map(|url| Reference {
                                    url: url.clone(),
                                    summary: url.to_string(),
                                    category: None,
                                })
                                .collect(),
                        )
                    },
                    source_lang: None,
                },
                product_tree: Some(ProductTree {
                    branches: Some(BranchesT(vec![Branch {
                        name: input.metadata.package.to_string(),
                        category: BranchCategory::ProductName,
                        product: None,
                        branches: Some(branches.all()),
                    }])),
                    full_product_names: None,
                    product_groups: None,
                    relationships: None,
                }),
                vulnerabilities: Some(vec![Vulnerability {
                    acknowledgments: None,
                    cve: if input.metadata.id.is_cve() {
                        Some(input.metadata.id.to_string())
                    } else {
                        None
                    },
                    cwe: None,
                    discovery_date: None,
                    flags: None,
                    ids: Some(vec![VulnerabilityId {
                        text: input.metadata.id.to_string(),
                        system_name: match input.metadata.id.kind() {
                            rustsec::advisory::IdKind::RustSec => "RUSTSEC",
                            rustsec::advisory::IdKind::Cve => "CVE",
                            rustsec::advisory::IdKind::Ghsa => "GHSA",
                            rustsec::advisory::IdKind::Talos => "Talos",
                            _ => "Other",
                        }
                        .to_string(),
                    }]),
                    involvements: None,
                    notes: Some(vec![Note {
                        category: NoteCategory::Description,
                        text: input.metadata.description,
                        audience: None,
                        title: None,
                    }]),
                    product_status: Some(ProductStatus {
                        first_affected: None,
                        first_fixed: None,
                        fixed: branches.patched.product_ids(),
                        known_affected: branches.vulnerable.product_ids(),
                        known_not_affected: branches.unaffected.product_ids(),
                        last_affected: None,
                        recommended: None,
                        under_investigation: None,
                    }),
                    references: None,
                    release_date: None,
                    remediations: if !branches.patched.0.is_empty() {
                        Some(vec![Remediation {
                            category: RemediationCategory::VendorFix,
                            details: "Updated crate versions available".to_string(),
                            date: None,
                            entitlements: None,
                            group_ids: None,
                            product_ids: branches.vulnerable.product_ids(),
                            restart_required: None,
                            url: None,
                        }])
                    } else {
                        None
                    },
                    scores: input.metadata.cvss.map(|b| {
                        vec![Score {
                            products: branches
                                .vulnerable
                                .product_ids()
                                // Case where no version is actually vulnerable
                                .unwrap_or_else(|| {
                                    println!("INVALID Product ID");
                                    vec![ProductIdT("INVALID".to_string())]
                                }),
                            cvss_v2: None,
                            cvss_v3: Some(b),
                        }]
                    }),
                    threats: None,
                    title: Some(input.metadata.title),
                }]),
            }
        }
    }

    struct BranchTracking {
        patched: BranchesT,
        unaffected: BranchesT,
        vulnerable: BranchesT,
    }

    impl BranchTracking {
        fn extract_branches(package: &str, versions: &Versions) -> Self {
            let mut output = Self {
                patched: BranchesT(Vec::new()),
                unaffected: BranchesT(Vec::new()),
                vulnerable: BranchesT(Vec::new()),
            };

            let mut id_counter: usize = 1;

            // While unread later, initalize here to prevent it from dropping at end of closure
            // where the directory is created if necessary.
            let mut _index_temp_dir = None;

            let index = crates_index::Index::new_cargo_default()
                .or_else(|_| {
                    _index_temp_dir = Some(tempfile::tempdir().expect(
                        "Creating a temporary directory for a crates index should succeed.",
                    ));
                    crates_index::Index::with_path(
                        _index_temp_dir.expect("Was just set").path(),
                        crates_index::INDEX_GIT_URL,
                    )
                })
                .expect(
                    "Either opening the default index or creating a temporary one should work.",
                );

            let registry_crate = index
                .crate_(package)
                .expect("Package name must match name from crates.io registry");

            let registry_versions = registry_crate.versions();

            // ASSUMPTION: A version can only be one of patched, unaffected, or affected
            // TODO: When I'm reaching for loop labels something has gone terribly wrong
            'outer: for version in registry_versions {
                let rustsec_version = IndexPackage::from(version).version;

                // TODO: DRY
                for pattern in versions.unaffected() {
                    if pattern.matches(&rustsec_version) {
                        output.unaffected.0.push(product_version_branch(
                            &rustsec_version,
                            package,
                            id_counter,
                        ));
                        id_counter += 1;
                        continue 'outer;
                    }
                }
                for pattern in versions.patched() {
                    if pattern.matches(&rustsec_version) {
                        output.patched.0.push(product_version_branch(
                            &rustsec_version,
                            package,
                            id_counter,
                        ));
                        id_counter += 1;
                        continue 'outer;
                    }
                }

                // At this point the version has matched none of the unaffected or patched patterns, so can be evaulated
                // as potentially vulnerable
                if versions.is_vulnerable(&rustsec_version) {
                    output.vulnerable.0.push(product_version_branch(
                        &rustsec_version,
                        package,
                        id_counter,
                    ));
                    id_counter += 1;
                }
            }

            output
        }

        fn all(&self) -> BranchesT {
            let mut output = BranchesT(Vec::new());
            output.0.append(&mut self.patched.0.clone());
            output.0.append(&mut self.unaffected.0.clone());
            output.0.append(&mut self.vulnerable.0.clone());
            output
        }
    }

    pub fn product_version_branch(
        version: impl ToString,
        package: &str,
        id_counter: usize,
    ) -> Branch {
        Branch {
            name: version.to_string(),
            category: BranchCategory::ProductVersion,
            product: Some(FullProductName {
                name: format!("{} {}", package, version.to_string()),
                product_id: ProductIdT(format!("{}-{}", package.to_uppercase(), id_counter)),
                product_identification_helper: Some(ProductIdentificationHelper {
                    cpe: Some(
                        cpe::uri::Uri::builder()
                            .part("a")
                            .vendor(&format!("{package}_project"))
                            .product(package)
                            .version(&version.to_string())
                            .validate()
                            .expect("Maps to valid CPE uri")
                            .to_owned(),
                    ),
                    hashes: None,
                    model_numbers: None,
                    purl: Some(
                        PackageUrl::new("cargo", package.to_string())
                            .unwrap()
                            .with_version(version.to_string())
                            .to_owned(),
                    ),
                    sbom_urls: None,
                    serial_numbers: None,
                    skus: None,
                    x_generic_uris: None,
                }),
            }),
            branches: None,
        }
    }

    #[cfg(test)]
    mod tests {
        use std::str::FromStr;

        use super::*;
        use serde_json;

        #[test]
        fn example_advisory_deserializes() {
            // TODO: Reuse
            let example = include_str!("../tests/RUSTSEC-2021-0093.md");
            let advisory = Advisory::from_str(example).unwrap();
            println!("{:#?}", advisory);
            let _document = crate::Csaf::from(advisory);
        }

        #[test]
        fn example_advisory_serializes() {
            let example = include_str!("../tests/RUSTSEC-2021-0093.md");
            let advisory = Advisory::from_str(example).unwrap();
            let document = crate::Csaf::from(advisory);
            println!("{}", serde_json::to_string_pretty(&document).unwrap());
        }

        #[test]
        #[ignore]
        fn walk_database() {
            let db = rustsec::database::Database::fetch()
                .expect("Need access to RustSec git repository");

            for advisory in db.into_iter() {
                println!(
                    "{} {} {:?}",
                    advisory.metadata.id, advisory.metadata.package, advisory.metadata.collection
                );
                let _document = crate::Csaf::from(advisory);
            }
        }
    }
}
