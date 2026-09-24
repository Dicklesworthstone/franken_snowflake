//! A live downstream adapter over the connector's local store (reality-check
//! bead oj0.39). It serves what `catalog scan`, `query run` and `export run`
//! persisted through [`SnowflakeDataLakeAdapter`], and profile diagnostics from
//! the profile's env handles, by name only. Every answer is offline; nothing
//! here talks to Snowflake. It passes
//! [`franken_snowflake_core::adapter::conformance`] like the fixture adapter.

use std::path::Path;

use franken_snowflake_cache::{CacheBackend, ContentAddress, ExportKind, FileCache};
use franken_snowflake_catalog::model::{
    CatalogSnapshot, DataSourceClass, DatasetManifest, DtypeClass, FieldRole, Provenance,
    RightsClass as CatalogRights,
};
use franken_snowflake_core::adapter::{
    ADAPTER_CATALOG_DISCOVERY_CONTRACT_ID, ADAPTER_CONTENT_EXPORT_CONTRACT_ID,
    ADAPTER_DATASET_MANIFEST_CONTRACT_ID, ADAPTER_FRAME_INGEST_CONTRACT_ID,
    ADAPTER_PROFILE_DIAGNOSTICS_CONTRACT_ID, ADAPTER_PROVIDER_MANIFEST_CONTRACT_ID,
    ADAPTER_QUERY_RECEIPT_CONTRACT_ID, AdapterProvenance, AdapterResult, AuthLaneContract,
    CatalogDiscoveryContract, ContentAddressRef, ContentExportContract, CredentialRefContract,
    CredentialRefKind, DataLakeKind, DatasetFieldContract, DatasetManifestContract,
    DtypeClassContract, ExportFormatContract, FieldRoleContract, FrameColumnContract,
    FrameIngestContract, ProfileDiagnosticStatus, ProfileDiagnostics, ProviderManifest,
    QueryReceiptContract, SnowflakeDataLakeAdapter, standard_output_contracts,
};
use franken_snowflake_core::envelope::{Envelope, EnvelopeMeta};
use franken_snowflake_core::error::{SnowflakeError, SnowflakeErrorCode};
use franken_snowflake_core::guardrails::RightsClass;
use franken_snowflake_core::ids::{
    DatasetId, ProfileName, QueryId, ReceiptHash, RequestId, StatementHandle,
};
use franken_snowflake_core::outcome::{DataSource, OutcomeKind};
use franken_snowflake_core::redact::redact;

use crate::catalog_surface::{DatasetLookupError, load_dataset};
use crate::local_store::{self, Store};

/// Reads an env handle by name; injectable so tests need not touch the
/// process environment.
pub type EnvLookup = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// [`SnowflakeDataLakeAdapter`] over the local store.
pub struct LocalStoreAdapter {
    store: Store,
    env: EnvLookup,
}

impl LocalStoreAdapter {
    /// Open the local store at the resolved data directory; profile
    /// diagnostics read the process environment.
    ///
    /// # Errors
    /// `CacheError` when no store can be opened.
    pub fn open() -> Result<Self, SnowflakeError> {
        Self::open_with_env(Box::new(|name| std::env::var(name).ok()))
    }

    /// [`Self::open`] with profile env handles read through `env`.
    ///
    /// # Errors
    /// `CacheError` when no store can be opened.
    pub fn open_with_env(env: EnvLookup) -> Result<Self, SnowflakeError> {
        let store = local_store::open_store().map_err(|error| {
            SnowflakeError::new(SnowflakeErrorCode::CacheError, error.message())
        })?;
        Ok(Self { store, env })
    }

    /// The store in `dir` (what `FRANKEN_SNOWFLAKE_DATA_DIR` names for the
    /// CLI), with profile env handles read through `env`.
    ///
    /// # Errors
    /// `CacheError` when the store cannot be opened.
    pub fn open_at(dir: &Path, env: EnvLookup) -> Result<Self, SnowflakeError> {
        let cache = FileCache::open(dir).map_err(cache_error)?;
        let store = Store {
            cache,
            dir: dir.to_path_buf(),
        };
        Ok(Self { store, env })
    }

    fn handle(&self, name: &str) -> Option<String> {
        (self.env)(name).filter(|value| !value.trim().is_empty())
    }
}

fn meta(command_id: &str, contract_id: &str, data_source: DataSource) -> EnvelopeMeta {
    let now = local_store::rfc3339_utc(local_store::now_unix_seconds());
    EnvelopeMeta::success(command_id, contract_id)
        .with_data_source(data_source)
        .with_timing(now.clone(), now, 0)
}

fn metadata_error(message: impl Into<String>) -> SnowflakeError {
    SnowflakeError::new(SnowflakeErrorCode::MetadataError, message)
}

fn cache_error(error: impl std::fmt::Display) -> SnowflakeError {
    SnowflakeError::new(SnowflakeErrorCode::CacheError, error.to_string())
}

fn address_ref(address: &ContentAddress) -> ContentAddressRef {
    ContentAddressRef {
        algorithm: address.algorithm.clone(),
        digest_hex: address.digest_hex.clone(),
        byte_len: address.byte_len,
    }
}

fn data_source(class: DataSourceClass) -> DataSource {
    match class {
        DataSourceClass::Live => DataSource::Live,
        DataSourceClass::Fixture => DataSource::Fixture,
        DataSourceClass::Empty => DataSource::Empty,
    }
}

fn provenance(provenance: &Provenance) -> AdapterProvenance {
    AdapterProvenance {
        data_source: data_source(provenance.data_source),
        command_id: provenance.command_id.clone(),
        trace_id: provenance.trace_id.clone(),
        fingerprint: provenance.profile_fingerprint.clone(),
    }
}

fn rights(class: CatalogRights) -> RightsClass {
    match class {
        CatalogRights::Public => RightsClass::Public,
        CatalogRights::Internal => RightsClass::Internal,
        CatalogRights::Private => RightsClass::Private,
        CatalogRights::Restricted => RightsClass::Restricted,
    }
}

fn role(role: FieldRole) -> FieldRoleContract {
    match role {
        FieldRole::EntityKey => FieldRoleContract::EntityKey,
        FieldRole::TimeIndex => FieldRoleContract::TimeIndex,
        FieldRole::KnownAt => FieldRoleContract::KnownAt,
        FieldRole::Feature => FieldRoleContract::Feature,
        FieldRole::Label => FieldRoleContract::Label,
        FieldRole::Metadata => FieldRoleContract::Metadata,
    }
}

/// The contract's six dtype classes: a time of day is temporal like a
/// timestamp, binary travels as hex text, and an unknown type is opaque.
fn dtype(class: DtypeClass) -> DtypeClassContract {
    match class {
        DtypeClass::String | DtypeClass::Binary => DtypeClassContract::String,
        DtypeClass::Number => DtypeClassContract::Number,
        DtypeClass::Boolean => DtypeClassContract::Boolean,
        DtypeClass::Date => DtypeClassContract::Date,
        DtypeClass::Time | DtypeClass::Timestamp => DtypeClassContract::Timestamp,
        DtypeClass::Variant | DtypeClass::Unknown => DtypeClassContract::Variant,
    }
}

/// A SQL API rowType type (`fixed`, `text`, `timestamp_ntz`, ...) as a
/// contract dtype.
fn wire_dtype(wire_type: &str) -> DtypeClassContract {
    match wire_type.to_ascii_lowercase().as_str() {
        "fixed" | "real" | "decfloat" | "number" => DtypeClassContract::Number,
        "text" | "binary" => DtypeClassContract::String,
        "boolean" => DtypeClassContract::Boolean,
        "date" => DtypeClassContract::Date,
        "time" | "timestamp_ntz" | "timestamp_ltz" | "timestamp_tz" => {
            DtypeClassContract::Timestamp
        }
        _ => DtypeClassContract::Variant,
    }
}

fn outcome(kind: &str) -> OutcomeKind {
    match kind {
        "ok" | "success" => OutcomeKind::Success,
        "cancelled" => OutcomeKind::Cancelled,
        "timeout" => OutcomeKind::Timeout,
        _ => OutcomeKind::Error,
    }
}

fn export_format(kind: &ExportKind) -> Option<ExportFormatContract> {
    match kind {
        ExportKind::CopyInto => Some(ExportFormatContract::CopyInto),
        ExportKind::LocalCsv => Some(ExportFormatContract::Csv),
        ExportKind::LocalJsonl => Some(ExportFormatContract::Jsonl),
        ExportKind::LocalParquet => Some(ExportFormatContract::Parquet),
        ExportKind::LocalFrame => None,
    }
}

/// The auth lane named by `<PREFIX>_AUTH` and the env handle of its secret.
fn lane(value: &str) -> Option<(AuthLaneContract, &'static str)> {
    match value.trim().to_ascii_lowercase().as_str() {
        "pat" | "programmatic_access_token" => {
            Some((AuthLaneContract::ProgrammaticAccessToken, "PAT"))
        }
        "key_pair_jwt" | "jwt" => Some((AuthLaneContract::KeyPairJwt, "PRIVATE_KEY_PEM")),
        "oauth" | "oauth_bearer" | "oauth_bearer_token" => {
            Some((AuthLaneContract::OAuthBearer, "OAUTH_BEARER"))
        }
        "workload_identity" | "workload_identity_federation" | "oidc" => {
            Some((AuthLaneContract::WorkloadIdentityFederation, "OIDC_TOKEN"))
        }
        _ => None,
    }
}

impl SnowflakeDataLakeAdapter for LocalStoreAdapter {
    fn provider_manifest(&self) -> AdapterResult<ProviderManifest> {
        Ok(Envelope::new(
            meta(
                "adapter.provider_manifest",
                ADAPTER_PROVIDER_MANIFEST_CONTRACT_ID,
                DataSource::Unspecified,
            ),
            ProviderManifest {
                schema: ADAPTER_PROVIDER_MANIFEST_CONTRACT_ID.to_owned(),
                provider_id: "snowflake_sql_api".to_owned(),
                display_name: "Snowflake SQL API (franken-snowflake local store)".to_owned(),
                data_lake_kind: DataLakeKind::SnowflakeSqlApi,
                authenticated_private_source: true,
                contracts: standard_output_contracts(),
                non_goals: vec![
                    "downstream adapters must not handle raw credentials".to_owned(),
                    "downstream adapters must not embed Snowflake protocol code".to_owned(),
                    "downstream adapters own their user-facing policy semantics".to_owned(),
                ],
            },
        ))
    }

    fn profile_diagnostics(&self, profile: &ProfileName) -> AdapterResult<ProfileDiagnostics> {
        let prefix = crate::profile_env_prefix(profile.as_str());
        let handle = |key: &str| self.handle(&format!("{prefix}_{key}"));
        let base = ["ACCOUNT", "USER", "AUTH", "WAREHOUSE"];
        if base.iter().all(|key| handle(key).is_none()) {
            return Err(SnowflakeError::new(
                SnowflakeErrorCode::ProfileNotFound,
                format!(
                    "profile `{}` has no env handles ({prefix}_ACCOUNT, _USER, _AUTH, _WAREHOUSE)",
                    profile.as_str()
                ),
            ));
        }
        let Some((auth_lane, secret_key)) = handle("AUTH").as_deref().and_then(lane) else {
            return Err(SnowflakeError::new(
                SnowflakeErrorCode::ProfileInvalid,
                format!(
                    "{prefix}_AUTH is unset or names an unsupported lane; use pat, key_pair_jwt, or oauth_bearer"
                ),
            ));
        };
        let mut missing: Vec<String> = base
            .iter()
            .filter(|key| handle(key).is_none())
            .map(|key| format!("{prefix}_{key}"))
            .collect();
        let secret_present = handle(secret_key).is_some()
            || (secret_key == "OIDC_TOKEN" && handle("OIDC_TOKEN_FILE").is_some());
        if !secret_present {
            missing.push(format!("{prefix}_{secret_key}"));
        }
        let status = if missing.is_empty() {
            ProfileDiagnosticStatus::Valid
        } else {
            ProfileDiagnosticStatus::CredentialMissing
        };
        Ok(Envelope::new(
            meta(
                "adapter.profile_diagnostics",
                ADAPTER_PROFILE_DIAGNOSTICS_CONTRACT_ID,
                DataSource::Unspecified,
            )
            .with_profile(profile.clone()),
            ProfileDiagnostics {
                profile_id: profile.clone(),
                status,
                auth_lane,
                credential_ref: CredentialRefContract {
                    kind: CredentialRefKind::Env,
                    handle: format!("{prefix}_{secret_key}"),
                },
                account_ref_redacted: "[redacted-account]".to_owned(),
                required_rights_class: RightsClass::Private,
                warnings: missing
                    .iter()
                    .map(|name| format!("required env handle {name} is unset"))
                    .collect(),
                error_codes: vec![
                    SnowflakeErrorCode::ProfileNotFound,
                    SnowflakeErrorCode::ProfileInvalid,
                    SnowflakeErrorCode::CredentialMissing,
                ],
            },
        ))
    }

    fn catalog_discovery(&self, profile: &ProfileName) -> AdapterResult<CatalogDiscoveryContract> {
        let record = self
            .store
            .cache
            .latest_catalog_snapshot(profile.as_str(), None, None)
            .map_err(cache_error)?
            .ok_or_else(|| {
                metadata_error(format!(
                    "no catalog snapshot for profile `{}` in the local store; run `franken-snowflake catalog scan {} --database <db> --schema <schema> --json`",
                    profile.as_str(),
                    profile.as_str()
                ))
            })?;
        let snapshot: CatalogSnapshot =
            serde_json::from_str(&record.payload.canonical).map_err(|error| {
                metadata_error(format!("the stored snapshot does not parse: {error}"))
            })?;
        let count = |len: usize| u32::try_from(len).unwrap_or(u32::MAX);
        let source = data_source(snapshot.provenance.data_source);
        Ok(Envelope::new(
            meta(
                "adapter.catalog_discovery",
                ADAPTER_CATALOG_DISCOVERY_CONTRACT_ID,
                source,
            )
            .with_profile(profile.clone()),
            CatalogDiscoveryContract {
                profile_id: profile.clone(),
                snapshot_id: record.snapshot_id.clone(),
                content_address: address_ref(&record.payload.address),
                dataset_count: count(snapshot.datasets.len()),
                column_count: count(snapshot.columns.len()),
                operator_count: count(snapshot.operators.len()),
                provenance: provenance(&snapshot.provenance),
            },
        ))
    }

    fn dataset_manifest(&self, dataset: &DatasetId) -> AdapterResult<DatasetManifestContract> {
        let stored = load_dataset(&self.store, dataset.as_str()).map_err(|error| match error {
            DatasetLookupError::Cache(error) => cache_error(error),
            DatasetLookupError::NotFound { dataset_id, .. } => metadata_error(format!(
                "dataset `{dataset_id}` is not in the local store; run a catalog scan for it"
            )),
            DatasetLookupError::Corrupt(detail) => {
                metadata_error(format!("local catalog metadata is unreadable: {detail}"))
            }
            DatasetLookupError::Overlay(error) => SnowflakeError::new(
                SnowflakeErrorCode::UsageError,
                format!(
                    "the dataset manifest overlay {} is invalid: {}",
                    error.path, error.message
                ),
            ),
        })?;
        let manifest: &DatasetManifest = &stored.manifest;
        let canonical = serde_json::to_string(manifest).map_err(|error| {
            SnowflakeError::new(SnowflakeErrorCode::Internal, error.to_string())
        })?;
        let source = data_source(manifest.provenance.data_source);
        Ok(Envelope::new(
            meta(
                "adapter.dataset_manifest",
                ADAPTER_DATASET_MANIFEST_CONTRACT_ID,
                source,
            )
            .with_profile(ProfileName::new(manifest.profile.clone())),
            DatasetManifestContract {
                dataset_id: dataset.clone(),
                profile_id: ProfileName::new(manifest.profile.clone()),
                object_ref_redacted: redact(&format!(
                    "{}.{}.{}",
                    manifest.database, manifest.schema, manifest.object
                ))
                .into_owned(),
                object_fingerprint: manifest.provenance.object_fingerprint.clone(),
                rights_class: rights(manifest.rights_class),
                default_limit: manifest.default_limit,
                max_rows_without_export: manifest.max_rows_without_export,
                fields: manifest
                    .fields
                    .iter()
                    .map(|field| DatasetFieldContract {
                        column: field.column.clone(),
                        role: role(field.role),
                        dtype: dtype(field.dtype),
                        required: field.required,
                    })
                    .collect(),
                // The address of what is served: the stored manifest with the
                // overlay applied.
                content_address: address_ref(&ContentAddress::blake3(canonical.as_bytes())),
                provenance: provenance(&manifest.provenance),
            },
        ))
    }

    fn query_receipt(&self, receipt: &ReceiptHash) -> AdapterResult<QueryReceiptContract> {
        let record = self
            .store
            .cache
            .query_receipt(receipt.as_str())
            .map_err(cache_error)?
            .ok_or_else(|| {
                metadata_error(format!(
                    "receipt `{}` is not in the local store",
                    receipt.as_str()
                ))
            })?;
        let body: serde_json::Value =
            serde_json::from_str(&record.receipt.canonical).unwrap_or_default();
        let dataset_id = body["dataset_id"]
            .as_str()
            .or_else(|| body["extra"]["dataset_id"].as_str())
            .map(DatasetId::new);
        let mut meta = meta(
            "adapter.query_receipt",
            ADAPTER_QUERY_RECEIPT_CONTRACT_ID,
            DataSource::Live,
        )
        .with_profile(ProfileName::new(record.profile_id.clone()));
        meta.receipt_hash = Some(receipt.clone());
        meta.statement_handle = record.statement_handle.clone().map(StatementHandle::new);
        meta.query_id = record.snowflake_query_id.clone().map(QueryId::new);
        Ok(Envelope::new(
            meta,
            QueryReceiptContract {
                receipt_hash: receipt.clone(),
                plan_id: record.plan_id.clone(),
                profile_id: ProfileName::new(record.profile_id.clone()),
                dataset_id,
                request_id: RequestId::new(
                    record
                        .request_id
                        .clone()
                        .unwrap_or_else(|| record.trace_id.clone()),
                ),
                query_id: record.snowflake_query_id.clone().map(QueryId::new),
                statement_handle: record.statement_handle.clone().map(StatementHandle::new),
                outcome_kind: outcome(&record.outcome_kind),
                rights_class: RightsClass::Private,
                row_count: record.row_count,
                content_address: address_ref(&record.receipt.address),
                redactions_applied: Vec::new(),
            },
        ))
    }

    fn content_export(&self, export_id: &str) -> AdapterResult<ContentExportContract> {
        let record = self
            .store
            .cache
            .export(export_id)
            .map_err(cache_error)?
            .ok_or_else(|| {
                metadata_error(format!("export `{export_id}` is not in the local store"))
            })?;
        let Some(format) = export_format(&record.export_kind) else {
            return Err(metadata_error(format!(
                "export `{export_id}` is a frame artifact; use frame_ingest"
            )));
        };
        let mut meta = meta(
            "adapter.content_export",
            ADAPTER_CONTENT_EXPORT_CONTRACT_ID,
            DataSource::Live,
        );
        meta.receipt_hash = Some(ReceiptHash::new(record.receipt_id.clone()));
        Ok(Envelope::new(
            meta,
            ContentExportContract {
                export_id: export_id.to_owned(),
                receipt_hash: ReceiptHash::new(record.receipt_id.clone()),
                format,
                target_uri_redacted: redact(&record.target_uri_redacted).into_owned(),
                content_address: address_ref(&record.content_address),
                row_count: record.row_count,
            },
        ))
    }

    fn frame_ingest(&self, frame_id: &str) -> AdapterResult<FrameIngestContract> {
        let record = self
            .store
            .cache
            .export(frame_id)
            .map_err(cache_error)?
            .filter(|record| record.export_kind == ExportKind::LocalFrame)
            .ok_or_else(|| {
                metadata_error(format!("frame `{frame_id}` is not in the local store"))
            })?;
        let receipt = self
            .store
            .cache
            .query_receipt(&record.receipt_id)
            .map_err(cache_error)?
            .ok_or_else(|| {
                metadata_error(format!(
                    "frame `{frame_id}` names a receipt the store lacks"
                ))
            })?;
        let body: serde_json::Value =
            serde_json::from_str(&receipt.receipt.canonical).unwrap_or_default();
        let columns = body["columns"]
            .as_array()
            .map(|columns| {
                columns
                    .iter()
                    .filter_map(|column| {
                        Some(FrameColumnContract {
                            name: column["name"].as_str()?.to_owned(),
                            dtype: wire_dtype(column["type"].as_str().unwrap_or_default()),
                            nullable: true,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut meta = meta(
            "adapter.frame_ingest",
            ADAPTER_FRAME_INGEST_CONTRACT_ID,
            DataSource::Live,
        );
        meta.receipt_hash = Some(ReceiptHash::new(record.receipt_id.clone()));
        Ok(Envelope::new(
            meta,
            FrameIngestContract {
                frame_id: frame_id.to_owned(),
                receipt_hash: ReceiptHash::new(record.receipt_id.clone()),
                columns,
                row_count: record.row_count,
                content_address: address_ref(&record.content_address),
                rights_class: RightsClass::Private,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_mappings_cover_every_catalog_class() {
        assert_eq!(dtype(DtypeClass::Time), DtypeClassContract::Timestamp);
        assert_eq!(dtype(DtypeClass::Binary), DtypeClassContract::String);
        assert_eq!(dtype(DtypeClass::Unknown), DtypeClassContract::Variant);
        assert_eq!(wire_dtype("FIXED"), DtypeClassContract::Number);
        assert_eq!(wire_dtype("timestamp_tz"), DtypeClassContract::Timestamp);
        assert_eq!(wire_dtype("object"), DtypeClassContract::Variant);
        assert_eq!(outcome("ok"), OutcomeKind::Success);
        assert_eq!(outcome("cancelled"), OutcomeKind::Cancelled);
        assert_eq!(outcome("anything else"), OutcomeKind::Error);
        assert_eq!(export_format(&ExportKind::LocalFrame), None);
        assert_eq!(
            lane("PAT"),
            Some((AuthLaneContract::ProgrammaticAccessToken, "PAT"))
        );
        assert_eq!(lane("password"), None);
        assert_eq!(rights(CatalogRights::Restricted), RightsClass::Restricted);
    }
}
