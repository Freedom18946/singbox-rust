//! Error handling for API services

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use sb_core::error::SbError;
use serde_json::json;
use thiserror::Error;

/// Result type for API operations
pub type ApiResult<T> = Result<T, ApiError>;

/// API error types
#[derive(Debug, Error)]
pub enum ApiError {
    /// Client sent a malformed or invalid request.
    #[error("Invalid request: {message}")]
    BadRequest {
        /// Human-readable error message.
        message: String,
    },

    /// Requested resource was not found.
    #[error("Not found: {resource}")]
    NotFound {
        /// Resource identifier that was not found.
        resource: String,
    },

    /// Internal server error. Underlying error source.
    #[error("Internal error: {source}")]
    Internal {
        /// Underlying error source.
        #[from]
        source: anyhow::Error,
    },

    /// Service is temporarily unavailable.
    #[error("Service unavailable: {message}")]
    ServiceUnavailable {
        /// Human-readable reason describing the service disruption.
        message: String,
    },

    /// Configuration-related error.
    #[error("Configuration error: {message}")]
    Configuration {
        /// Problem detail associated with configuration.
        message: String,
    },

    /// JSON serialization/deserialization failure. Underlying error source.
    #[error("JSON error: {source}")]
    Json {
        /// Underlying error source.
        #[from]
        source: serde_json::Error,
    },

    /// WebSocket error.
    #[error("WebSocket error: {message}")]
    WebSocket {
        /// Human-readable error message for WebSocket operations.
        message: String,
    },

    /// Parsing error.
    #[error("Parse error: {message}")]
    Parse {
        /// Human-readable parsing error message.
        message: String,
    },

    /// Invalid field in API input.
    #[error("Invalid field '{field}': {message}")]
    InvalidField {
        /// Name of the invalid field.
        field: String,
        /// Explanation of why the field is invalid.
        message: String,
    },

    /// Unsupported API version.
    #[error("Unsupported version: {version}")]
    UnsupportedVersion {
        /// The version string that is not supported.
        version: String,
    },
}

impl ApiError {
    /// Stable kind string for logging/assertions
    pub fn kind(&self) -> &'static str {
        match self {
            ApiError::BadRequest { .. } => "BadRequest",
            ApiError::NotFound { .. } => "NotFound",
            ApiError::Internal { .. } => "Internal",
            ApiError::ServiceUnavailable { .. } => "ServiceUnavailable",
            ApiError::Configuration { .. } => "Configuration",
            ApiError::Json { .. } => "Json",
            ApiError::WebSocket { .. } => "WebSocket",
            ApiError::Parse { .. } => "Parse",
            ApiError::InvalidField { .. } => "InvalidField",
            ApiError::UnsupportedVersion { .. } => "UnsupportedVersion",
        }
    }

    /// Example
    /// ```
    /// use sb_api::error::ApiError;
    /// let e = ApiError::bad_request("missing field");
    /// assert_eq!(e.status_code(), axum::http::StatusCode::BAD_REQUEST);
    /// ```
    /// Create a bad request error
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest {
            message: message.into(),
        }
    }

    /// Create a not found error
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::NotFound {
            resource: resource.into(),
        }
    }

    /// Create a service unavailable error
    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self::ServiceUnavailable {
            message: message.into(),
        }
    }

    /// Create a configuration error
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }

    /// Create a WebSocket error
    pub fn websocket(message: impl Into<String>) -> Self {
        Self::WebSocket {
            message: message.into(),
        }
    }

    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::BadRequest { .. } => StatusCode::BAD_REQUEST,
            ApiError::NotFound { .. } => StatusCode::NOT_FOUND,
            ApiError::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Configuration { .. } => StatusCode::BAD_REQUEST,
            ApiError::Json { .. } => StatusCode::BAD_REQUEST,
            ApiError::WebSocket { .. } => StatusCode::BAD_REQUEST,
            ApiError::Parse { .. } => StatusCode::BAD_REQUEST,
            ApiError::InvalidField { .. } => StatusCode::BAD_REQUEST,
            ApiError::UnsupportedVersion { .. } => StatusCode::BAD_REQUEST,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status_code = self.status_code();
        let error_message = self.to_string();

        let body = Json(json!({
            "error": error_message,
            "code": status_code.as_u16()
        }));

        (status_code, body).into_response()
    }
}

impl From<SbError> for ApiError {
    fn from(e: SbError) -> Self {
        // Preserve source via anyhow wrapping, keep external signature intact
        ApiError::Internal {
            source: anyhow::Error::from(e),
        }
    }
}
