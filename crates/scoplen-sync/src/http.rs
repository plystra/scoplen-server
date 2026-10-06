// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated HTTP/CBOR adapter for the K-4 sync service.
//!
//! This module owns request validation, wire decoding, storage error mapping, and response
//! encoding. It deliberately does not implement identity. A deployment must provide an
//! authenticator that validates the DPoP-bound access token and authorizes the requested vault
//! operation before this router is mounted on the public listener.

#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use scoplen_api::{ErrorCode, ProblemDetails, sync as api};
use scoplen_model::cbor::{self, Value};
use scoplen_store::{SqliteStore, sync as storage};
use uuid::{Uuid, Variant};

/// The maximum request body accepted by the write endpoint. The CBOR codec applies the same
/// limit before decoding, and the router applies it before allocating a handler body.
pub const MAX_REQUEST_BYTES: usize = storage::MAX_BATCH_BYTES;

/// The operation requested from the authenticator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncOperation {
    /// Read the current change feed.
    Read,
    /// Read a full reconciliation snapshot.
    Snapshot,
    /// Read retained object versions.
    Versions,
    /// Write object envelopes.
    Write,
    /// Advance a device acknowledgement cursor.
    Acknowledge,
}

/// An authenticated device identity supplied by the identity service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedDevice {
    /// `UUIDv7` of the enrolled device.
    pub device_id: storage::DeviceId,
}

/// A problem returned by an authenticator at the request boundary.
#[derive(Clone, Debug)]
pub struct AuthFailure {
    /// HTTP status to return.
    pub status: StatusCode,
    /// Registered or syntactically valid future error code.
    pub code: ErrorCode,
    /// Human-readable title for diagnostics.
    pub title: String,
    /// Human-readable detail; clients must not parse it.
    pub detail: String,
    /// Whether retrying with the same request may succeed.
    pub retryable: bool,
}

impl AuthFailure {
    /// Construct an authentication failure after validating the code and text fields.
    ///
    /// # Errors
    ///
    /// Returns an error when the code is not a valid dotted lower-case code or a required text
    /// field is empty. The identity service should use a code from the K-3 registry.
    pub fn new(
        status: StatusCode,
        code: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
        retryable: bool,
    ) -> Result<Self, String> {
        let code = ErrorCode::new(code.into()).map_err(|error| error.to_string())?;
        let title = title.into();
        let detail = detail.into();
        if title.trim().is_empty() || detail.trim().is_empty() {
            return Err("authentication problem text must not be empty".into());
        }
        Ok(Self { status, code, title, detail, retryable })
    }
}

/// Identity and authorization boundary required by the sync HTTP adapter.
///
/// Implementations MUST validate the Authorization `DPoP` access token and its accompanying
/// `DPoP` proof before returning an identity. They MUST reject missing, malformed, expired, or revoked
/// credentials and enforce vault membership for the requested operation. This trait has no
/// default implementation so the server cannot accidentally ship an unauthenticated endpoint.
pub trait SyncAuthenticator: Clone + Send + Sync + 'static {
    /// Authenticate the request headers as one enrolled device.
    ///
    /// # Errors
    ///
    /// Returns an authentication problem when the access token or proof is missing, invalid,
    /// expired, or revoked.
    fn authenticate(&self, headers: &HeaderMap) -> Result<AuthenticatedDevice, AuthFailure>;

    /// Authorize the device for one vault operation.
    ///
    /// # Errors
    ///
    /// Returns a policy or authentication problem when the device cannot perform the operation.
    fn authorize(
        &self,
        identity: AuthenticatedDevice,
        vault: storage::VaultId,
        operation: SyncOperation,
    ) -> Result<(), AuthFailure>;
}

/// Build the K-4 router with an explicit authentication implementation.
///
/// The returned router is not mounted by the baseline server listener until identity V3 is
/// available. Tests and a future identity service can mount it with their own authenticator.
pub fn router<A: SyncAuthenticator>(store: Arc<SqliteStore>, authenticator: A) -> Router {
    let state = SyncHttpState { store, authenticator };
    Router::new()
        .route("/sync/v1/vaults/{vault}/changes", get(changes::<A>))
        .route("/sync/v1/vaults/{vault}/snapshot", get(snapshot::<A>))
        .route("/sync/v1/vaults/{vault}/objects/{object}/versions", get(versions::<A>))
        .route("/sync/v1/vaults/{vault}/objects", post(objects::<A>))
        .route("/sync/v1/vaults/{vault}/ack", post(ack::<A>))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state)
}

#[derive(Clone)]
struct SyncHttpState<A> {
    store: Arc<SqliteStore>,
    authenticator: A,
}

async fn changes<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity = authorize(&state, &headers, vault, SyncOperation::Read, &instance)?;
    let query = parse_query(query, &instance)?;
    let page = state
        .store
        .sync_changes(vault, query.after, query.limit)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncChangesResponse {
        changes: page.changes.into_iter().map(change_to_api).collect(),
        next_cursor: page.next_cursor,
        more: page.more,
    };
    response.validate_for_query(&query).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid change page: {error}"))
    })?;
    let _ = identity;
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode change page: {error}"))
    })?))
}

async fn snapshot<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity = authorize(&state, &headers, vault, SyncOperation::Snapshot, &instance)?;
    let query = parse_query(query, &instance)?;
    let page = state
        .store
        .sync_snapshot(vault, query.after, query.limit)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncSnapshotResponse {
        objects: page.objects.into_iter().map(change_to_api).collect(),
        next_cursor: page.next_cursor,
        more: page.more,
    };
    response.validate_for_query(&query).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid snapshot page: {error}"))
    })?;
    let _ = identity;
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode snapshot page: {error}"))
    })?))
}

async fn versions<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path((vault, object)): Path<(String, String)>,
    headers: HeaderMap,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let object = parse_uuid(&object, "object", &instance)?;
    let identity = authorize(&state, &headers, vault, SyncOperation::Versions, &instance)?;
    let versions = state
        .store
        .sync_versions(vault, object)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response =
        api::SyncVersionsResponse { versions: versions.into_iter().map(change_to_api).collect() };
    response.validate_for_object(Uuid::from_bytes(object)).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid version response: {error}"))
    })?;
    let _ = identity;
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode versions: {error}"))
    })?))
}

async fn objects<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    require_cbor(&headers, &instance)?;
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity = authorize(&state, &headers, vault, SyncOperation::Write, &instance)?;
    if state
        .store
        .sync_vault_kind(vault)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?
        == storage::VaultKind::Organization
    {
        return Err(SyncHttpError::known(
            &instance,
            StatusCode::FORBIDDEN,
            "sync.read_only",
            "Vault is read-only",
            "Organization vaults are authored by the server; no data changed and retrying will not help.",
            false,
            false,
        ));
    }
    if body.len() > MAX_REQUEST_BYTES {
        return Err(SyncHttpError::invalid(&instance, "write batch exceeds 4 MiB"));
    }
    let batch = api::SyncWriteBatch::from_cbor(&body).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid write batch: {error}"))
    })?;
    let total_bytes = batch.writes.iter().try_fold(0_usize, |total, write| {
        if write.payload.is_empty() || write.payload.len() > storage::MAX_ENVELOPE_BYTES {
            return None;
        }
        total.checked_add(write.payload.len())
    });
    if total_bytes.is_none_or(|total| total > storage::MAX_BATCH_BYTES) {
        return Err(SyncHttpError::invalid(&instance, "write envelopes exceed the sync limits"));
    }
    let writes = batch
        .writes
        .iter()
        .map(|write| storage::ObjectWrite {
            object_id: write.object_id.into_bytes(),
            base_sequence: write.base_seq,
            envelope: write.payload.clone(),
            tombstone: write.tombstone,
            signer_device_id: Some(identity.device_id),
        })
        .collect::<Vec<_>>();
    let receipts = state
        .store
        .write_sync_batch(vault, &writes)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncWriteBatchResponse {
        assignments: receipts
            .into_iter()
            .map(|receipt| api::SyncWriteAssignment {
                object_id: Uuid::from_bytes(receipt.object_id),
                seq: receipt.sequence,
            })
            .collect(),
    };
    response.validate_for_batch(&batch).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid write assignment: {error}"))
    })?;
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode write assignment: {error}"))
    })?))
}

async fn ack<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    require_cbor(&headers, &instance)?;
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity = authorize(&state, &headers, vault, SyncOperation::Acknowledge, &instance)?;
    let request = api::SyncAckRequest::from_cbor(&body).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid acknowledgement: {error}"))
    })?;
    let cursor = state
        .store
        .ack_sync_cursor(vault, identity.device_id, request.cursor)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    Ok(cbor_response(api::SyncAckResponse { cursor }.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode acknowledgement: {error}"))
    })?))
}

fn authorize<A: SyncAuthenticator>(
    state: &SyncHttpState<A>,
    headers: &HeaderMap,
    vault: storage::VaultId,
    operation: SyncOperation,
    instance: &str,
) -> SyncResult<AuthenticatedDevice> {
    let identity = state
        .authenticator
        .authenticate(headers)
        .map_err(|error| SyncHttpError::from_auth(error, instance))?;
    state
        .authenticator
        .authorize(identity, vault, operation)
        .map_err(|error| SyncHttpError::from_auth(error, instance))?;
    Ok(identity)
}

fn parse_query(raw: Option<String>, instance: &str) -> SyncResult<api::SyncChangesQuery> {
    let raw =
        raw.ok_or_else(|| SyncHttpError::invalid(instance, "after and limit are required"))?;
    api::SyncChangesQuery::from_query(&raw)
        .map_err(|error| SyncHttpError::invalid(instance, format!("invalid sync query: {error}")))
}

fn parse_uuid(value: &str, field: &str, instance: &str) -> SyncResult<storage::VaultId> {
    let id = Uuid::parse_str(value).map_err(|_| {
        SyncHttpError::invalid(instance, format!("{field} must be a canonical UUIDv7"))
    })?;
    if id.to_string() != value || id.get_version_num() != 7 || id.get_variant() != Variant::RFC4122
    {
        return Err(SyncHttpError::invalid(
            instance,
            format!("{field} must be a canonical UUIDv7"),
        ));
    }
    Ok(*id.as_bytes())
}

fn require_cbor(headers: &HeaderMap, instance: &str) -> SyncResult<()> {
    let content_type =
        headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).unwrap_or_default();
    if content_type != "application/cbor" {
        return Err(SyncHttpError::invalid(
            instance,
            "request Content-Type must be application/cbor",
        ));
    }
    Ok(())
}

fn change_to_api(change: storage::SyncChange) -> api::SyncChange {
    api::SyncChange {
        object_id: Uuid::from_bytes(change.object_id),
        seq: change.sequence,
        payload: change.envelope,
        tombstone: change.tombstone,
        signer_device_id: change.signer_device_id.map(Uuid::from_bytes),
    }
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| byte.is_ascii_graphic() && byte != b' ')
        })
        .map_or_else(|| Uuid::new_v4().to_string(), ToOwned::to_owned)
}

fn cbor_response(body: Vec<u8>) -> Response {
    let content_type = HeaderValue::from_static("application/cbor");
    (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], body).into_response()
}

type SyncResult<T> = Result<T, Box<SyncHttpError>>;

#[derive(Debug)]
struct SyncHttpError {
    status: StatusCode,
    problem: ProblemDetails,
    body: Option<Vec<u8>>,
}

impl SyncHttpError {
    fn from_auth(error: AuthFailure, instance: &str) -> Box<Self> {
        Self::known(
            instance,
            error.status,
            error.code.as_str(),
            error.title,
            error.detail,
            false,
            error.retryable,
        )
    }

    fn from_store(error: storage::SyncStoreError, instance: &str) -> Box<Self> {
        match error {
            storage::SyncStoreError::VaultNotFound | storage::SyncStoreError::ObjectNotFound => {
                Self::known(
                    instance,
                    StatusCode::NOT_FOUND,
                    "sync.object_not_found",
                    "Sync object not found",
                    "The requested sync resource does not exist; no data changed and retrying will not help.",
                    false,
                    false,
                )
            }
            storage::SyncStoreError::CursorExpired { purge_horizon } => Self::known(
                instance,
                StatusCode::GONE,
                "sync.cursor_expired",
                "Sync cursor expired",
                format!(
                    "The cursor is below the purge horizon ({purge_horizon}); no data changed and a full snapshot is required."
                ),
                false,
                false,
            ),
            storage::SyncStoreError::CursorAhead { cursor, current } => Self::known(
                instance,
                StatusCode::BAD_REQUEST,
                "sync.cursor_ahead",
                "Sync cursor is ahead",
                format!(
                    "Cursor {cursor} is ahead of the current sequence {current}; no data changed and retrying without a lower cursor will not help."
                ),
                false,
                false,
            ),
            storage::SyncStoreError::Conflict { conflicts } => {
                let problem = Self::known(
                    instance,
                    StatusCode::CONFLICT,
                    "sync.conflict",
                    "Sync write conflict",
                    "One or more objects changed; no data changed and merge the returned current versions before retrying.",
                    false,
                    true,
                );
                problem.with_conflicts(&conflicts)
            }
            storage::SyncStoreError::EmptyBatch
            | storage::SyncStoreError::BatchObjectLimit
            | storage::SyncStoreError::BatchByteLimit
            | storage::SyncStoreError::InvalidEnvelope
            | storage::SyncStoreError::DuplicateObject
            | storage::SyncStoreError::InvalidPageSize => {
                Self::invalid(instance, error.to_string())
            }
            storage::SyncStoreError::Constraint(_)
            | storage::SyncStoreError::SequenceExhausted
            | storage::SyncStoreError::CorruptRow(_)
            | storage::SyncStoreError::Database(_) => Self::known(
                instance,
                StatusCode::INTERNAL_SERVER_ERROR,
                "sync.storage_unavailable",
                "Sync service unavailable",
                "The server could not complete the sync request; no data changed and retrying may help.",
                false,
                true,
            ),
        }
    }

    fn invalid(instance: &str, detail: impl Into<String>) -> Box<Self> {
        Self::known(
            instance,
            StatusCode::BAD_REQUEST,
            "sync.invalid_request",
            "Invalid sync request",
            detail,
            false,
            false,
        )
    }

    fn known(
        instance: &str,
        status: StatusCode,
        code: &str,
        title: impl Into<String>,
        detail: impl Into<String>,
        changed: bool,
        retryable: bool,
    ) -> Box<Self> {
        let code = ErrorCode::new(code).expect("sync HTTP error code must be syntactically valid");
        let problem =
            ProblemDetails::new(code, status.as_u16(), title, detail, instance, changed, retryable)
                .expect("sync HTTP problem details must be valid");
        Box::new(Self { status, problem, body: None })
    }

    fn with_conflicts(mut self: Box<Self>, conflicts: &[storage::ConflictEntry]) -> Box<Self> {
        self.body = encode_conflicts(&self.problem, conflicts).ok();
        self
    }
}

impl IntoResponse for Box<SyncHttpError> {
    fn into_response(self) -> Response {
        let body = self.body.clone().unwrap_or_else(|| {
            self.problem.to_cbor().expect("validated sync HTTP problem must encode")
        });
        (
            self.status,
            [(header::CONTENT_TYPE, HeaderValue::from_static("application/problem+cbor"))],
            body,
        )
            .into_response()
    }
}

fn encode_conflicts(
    problem: &ProblemDetails,
    conflicts: &[storage::ConflictEntry],
) -> Result<Vec<u8>, String> {
    let Value::Map(mut fields) =
        cbor::decode(&problem.to_cbor().map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?
    else {
        return Err("problem details did not encode as a map".into());
    };
    // The adapter keeps an entry for every stale object. A missing current row is represented by
    // an explicit null so clients can distinguish it from a truncated conflict response.
    let entries = conflicts
        .iter()
        .map(|conflict| {
            let current = conflict.current.as_ref().map(|change| {
                Value::Map(vec![
                    (Value::UInt(1), Value::Bytes(change.object_id.to_vec())),
                    (Value::UInt(2), Value::UInt(change.sequence)),
                    (Value::UInt(3), Value::Bytes(change.envelope.clone())),
                    (Value::UInt(4), Value::Bool(change.tombstone)),
                    (
                        Value::UInt(5),
                        change.signer_device_id.map_or(Value::Null, |id| Value::Bytes(id.to_vec())),
                    ),
                ])
            });
            Value::Map(vec![
                (Value::Text("object_id".into()), Value::Bytes(conflict.object_id.to_vec())),
                (Value::Text("current".into()), current.unwrap_or(Value::Null)),
            ])
        })
        .collect();
    fields.push((Value::Text("conflicts".into()), Value::Array(entries)));
    cbor::encode(&Value::Map(fields)).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header::AUTHORIZATION};
    use scoplen_api::sync::{
        SyncAckRequest, SyncChangesResponse, SyncWriteBatch, SyncWriteBatchResponse,
    };
    use tower::ServiceExt;

    use super::*;

    #[derive(Clone)]
    struct TestAuthenticator {
        device_id: storage::DeviceId,
        allowed: bool,
    }

    impl SyncAuthenticator for TestAuthenticator {
        fn authenticate(&self, headers: &HeaderMap) -> Result<AuthenticatedDevice, AuthFailure> {
            if headers.get(AUTHORIZATION).and_then(|value| value.to_str().ok())
                != Some("DPoP test-token")
                || headers.get("dpop").is_none()
            {
                return Err(AuthFailure::new(
                    StatusCode::UNAUTHORIZED,
                    "auth.authentication_required",
                    "Authentication required",
                    "A DPoP-bound access token and proof are required; no data changed and retry after authentication.",
                    false,
                )
                .expect("test auth failure"));
            }
            Ok(AuthenticatedDevice { device_id: self.device_id })
        }

        fn authorize(
            &self,
            _identity: AuthenticatedDevice,
            _vault: storage::VaultId,
            _operation: SyncOperation,
        ) -> Result<(), AuthFailure> {
            if self.allowed {
                Ok(())
            } else {
                Err(AuthFailure::new(
                    StatusCode::FORBIDDEN,
                    "policy.denied",
                    "Sync access denied",
                    "The device is not authorized for this vault; no data changed and retrying will not help.",
                    false,
                )
                .expect("test policy failure"))
            }
        }
    }

    async fn test_store() -> (Arc<SqliteStore>, storage::VaultId, storage::DeviceId) {
        let path = std::env::temp_dir().join(format!("scoplen-http-{}", Uuid::new_v4()));
        let store = SqliteStore::open(&path).await.expect("open store");
        let vault = Uuid::now_v7().into_bytes();
        let device = Uuid::now_v7().into_bytes();
        store.create_sync_vault(vault, storage::VaultKind::Personal).await.expect("create vault");
        (Arc::new(store), vault, device)
    }

    fn path(id: storage::VaultId) -> String {
        Uuid::from_bytes(id).to_string()
    }

    fn request_headers(builder: axum::http::request::Builder) -> axum::http::request::Builder {
        builder.header(AUTHORIZATION, "DPoP test-token").header("dpop", "test-proof")
    }

    #[tokio::test]
    async fn changes_ack_and_write_round_trip_through_cbor() {
        let (store, vault, device) = test_store().await;
        let app = router(store.clone(), TestAuthenticator { device_id: device, allowed: true });
        let object = Uuid::now_v7();
        let write = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: object,
                base_seq: None,
                payload: vec![1, 2, 3],
                tombstone: false,
            }],
        };
        let request = request_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/objects", path(vault)))
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(write.to_cbor().expect("encode write")))
        .expect("request");
        let response = app.clone().oneshot(request).await.expect("write response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("write body");
        let assignments =
            SyncWriteBatchResponse::from_cbor(&body).expect("write assignments response");
        assert_eq!(assignments.assignments[0].object_id, object);

        let request = request_headers(
            Request::builder()
                .uri(format!("/sync/v1/vaults/{}/changes?after=0&limit=10", path(vault))),
        )
        .body(Body::empty())
        .expect("request");
        let response = app.clone().oneshot(request).await.expect("changes response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("changes body");
        let changes = SyncChangesResponse::from_cbor(&body).expect("changes response");
        assert_eq!(changes.changes.len(), 1);
        assert_eq!(changes.changes[0].object_id, object);

        let ack = SyncAckRequest { cursor: changes.next_cursor }.to_cbor().expect("ack");
        let request = request_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/ack", path(vault)))
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(ack))
        .expect("request");
        let response = app.oneshot(request).await.expect("ack response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(store.ping().await.is_ok());
    }

    #[tokio::test]
    async fn rejects_auth_content_type_query_and_ahead_cursor() {
        let (store, vault, device) = test_store().await;
        let app = router(store, TestAuthenticator { device_id: device, allowed: true });
        let request = Request::builder()
            .uri(format!("/sync/v1/vaults/{}/changes?after=00&limit=1", path(vault)))
            .body(Body::empty())
            .expect("request");
        let response = app.clone().oneshot(request).await.expect("auth response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("auth body");
        let problem = ProblemDetails::from_cbor(&body).expect("auth problem details");
        assert_eq!(problem.code.as_str(), "auth.authentication_required");

        let request = request_headers(
            Request::builder().uri(format!("/sync/v1/vaults/{}/changes?after=0", path(vault))),
        )
        .body(Body::empty())
        .expect("request");
        let response = app.clone().oneshot(request).await.expect("query response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("query body");
        let problem = ProblemDetails::from_cbor(&body).expect("query problem");
        assert_eq!(problem.code.as_str(), "sync.invalid_request");

        let request = request_headers(
            Request::builder().method("POST").uri(format!("/sync/v1/vaults/{}/ack", path(vault))),
        )
        .body(Body::from(SyncAckRequest { cursor: 0 }.to_cbor().expect("ack")))
        .expect("request");
        let response = app.clone().oneshot(request).await.expect("content type response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let request = request_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/ack", path(vault)))
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(SyncAckRequest { cursor: 1 }.to_cbor().expect("ack")))
        .expect("request");
        let response = app.oneshot(request).await.expect("ahead response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("ahead body");
        let problem = ProblemDetails::from_cbor(&body).expect("ahead problem");
        assert_eq!(problem.code.as_str(), "sync.cursor_ahead");
    }

    #[tokio::test]
    async fn conflict_problem_contains_current_change_extension() {
        let (store, vault, device) = test_store().await;
        let app = router(store, TestAuthenticator { device_id: device, allowed: true });
        let object = Uuid::now_v7();
        let make_request = |batch: SyncWriteBatch| {
            request_headers(
                Request::builder()
                    .method("POST")
                    .uri(format!("/sync/v1/vaults/{}/objects", path(vault)))
                    .header(header::CONTENT_TYPE, "application/cbor"),
            )
            .body(Body::from(batch.to_cbor().expect("encode batch")))
            .expect("request")
        };
        let first = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: object,
                base_seq: None,
                payload: vec![1],
                tombstone: false,
            }],
        };
        assert_eq!(
            app.clone().oneshot(make_request(first)).await.expect("first").status(),
            StatusCode::OK
        );
        let stale = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: object,
                base_seq: None,
                payload: vec![2],
                tombstone: false,
            }],
        };
        let response = app.clone().oneshot(make_request(stale)).await.expect("conflict");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("conflict body");
        let Value::Map(fields) = cbor::decode(&body).expect("problem cbor") else {
            panic!("problem is map");
        };
        let conflicts = fields
            .into_iter()
            .find_map(|(key, value)| (key == Value::Text("conflicts".into())).then_some(value));
        assert!(matches!(conflicts, Some(Value::Array(values)) if values.len() == 1));

        let absent_object = Uuid::now_v7();
        let absent = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: absent_object,
                base_seq: Some(1),
                payload: vec![3],
                tombstone: false,
            }],
        };
        let response = app.oneshot(make_request(absent)).await.expect("absent conflict");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("absent conflict body");
        let Value::Map(fields) = cbor::decode(&body).expect("absent conflict cbor") else {
            panic!("problem is map");
        };
        let Some(Value::Array(entries)) = fields
            .into_iter()
            .find_map(|(key, value)| (key == Value::Text("conflicts".into())).then_some(value))
        else {
            panic!("conflict extension is missing");
        };
        assert_eq!(entries.len(), 1);
        let Value::Map(entry) = &entries[0] else {
            panic!("conflict entry is not a map");
        };
        assert!(entry.iter().any(|(key, value)| {
            key == &Value::Text("current".into()) && value == &Value::Null
        }));
    }

    #[tokio::test]
    async fn policy_denied_before_storage_and_organization_is_read_only() {
        let (store, vault, device) = test_store().await;
        let app = router(store.clone(), TestAuthenticator { device_id: device, allowed: false });
        let request = request_headers(
            Request::builder()
                .uri(format!("/sync/v1/vaults/{}/changes?after=0&limit=1", path(vault))),
        )
        .body(Body::empty())
        .expect("request");
        let response = app.oneshot(request).await.expect("denied response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let organization_vault = Uuid::now_v7().into_bytes();
        store
            .create_sync_vault(organization_vault, storage::VaultKind::Organization)
            .await
            .expect("create organization vault");
        let app = router(store.clone(), TestAuthenticator { device_id: device, allowed: true });
        let write = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: Uuid::now_v7(),
                base_seq: None,
                payload: vec![1],
                tombstone: false,
            }],
        };
        let request = request_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/objects", path(organization_vault)))
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(write.to_cbor().expect("encode write")))
        .expect("request");
        let response = app.oneshot(request).await.expect("read-only response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("read-only body");
        let problem = ProblemDetails::from_cbor(&body).expect("read-only problem");
        assert_eq!(problem.code.as_str(), "sync.read_only");
        assert!(store.ping().await.is_ok());
    }
}
