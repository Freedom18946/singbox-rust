//! JWT authentication provider with JWKS support
//!
//! This provider supports JSON Web Token (JWT) authentication with:
//! - RS256/ES256 public key verification (preferred)
//! - HS256 symmetric key verification (optional)
//! - JWKS (JSON Web Key Set) caching and rotation
//! - Clock skew tolerance
//! - Algorithm allowlist security
//! - Fallback to cached JWKS on fetch failures

use super::{AuthError, AuthProvider};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use parking_lot::RwLock;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[cfg(feature = "jwt")]
use jsonwebtoken::{
    decode, decode_header, errors::ErrorKind as JwtErrorKind, Algorithm, DecodingKey, TokenData,
    Validation,
};

#[cfg(feature = "jwt")]
use rsa::pkcs1::EncodeRsaPublicKey;

#[cfg(feature = "jwt")]
use p256::elliptic_curve::sec1::FromEncodedPoint;

#[cfg(feature = "jwt")]
use pkcs8::EncodePublicKey;

#[cfg(feature = "jwt")]
use pkcs1;

/// JWT algorithm support levels
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtAlgorithm {
    /// RSA with SHA-256 (RS256) - recommended for asymmetric
    RS256,
    /// ECDSA with P-256 and SHA-256 (ES256) - recommended for asymmetric
    ES256,
    /// HMAC with SHA-256 (HS256) - symmetric, use with caution
    HS256,
}

impl JwtAlgorithm {
    /// Parse algorithm from string
    pub fn from_str(s: &str) -> Result<Self, AuthError> {
        match s.to_uppercase().as_str() {
            "RS256" => Ok(Self::RS256),
            "ES256" => Ok(Self::ES256),
            "HS256" => Ok(Self::HS256),
            "NONE" | "NULL" | "" => Err(AuthError::invalid(
                "Algorithm 'none' is not allowed for security reasons",
            )),
            other => Err(AuthError::invalid(format!(
                "Unsupported JWT algorithm: {}",
                other
            ))),
        }
    }

    #[cfg(feature = "jwt")]
    /// Convert to jsonwebtoken Algorithm
    fn to_jsonwebtoken_algorithm(&self) -> Algorithm {
        match self {
            Self::RS256 => Algorithm::RS256,
            Self::ES256 => Algorithm::ES256,
            Self::HS256 => Algorithm::HS256,
        }
    }
}

/// JWKS (JSON Web Key Set) entry
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct JsonWebKey {
    /// Key type (e.g., "RSA", "EC")
    kty: String,
    /// Key ID (optional)
    kid: Option<String>,
    /// Algorithm (optional)
    alg: Option<String>,
    /// RSA modulus (for RSA keys)
    n: Option<String>,
    /// RSA exponent (for RSA keys)
    e: Option<String>,
    /// Curve name (for EC keys)
    crv: Option<String>,
    /// X coordinate (for EC keys)
    x: Option<String>,
    /// Y coordinate (for EC keys)
    y: Option<String>,
}

/// JWKS response format
#[derive(Debug, Clone, Deserialize)]
struct JwksResponse {
    keys: Vec<JsonWebKey>,
}

/// Cached JWKS data
#[derive(Debug, Clone)]
struct CachedJwks {
    /// The JWKS response
    jwks: JwksResponse,
    /// When this cache entry was created
    cached_at: SystemTime,
    /// TTL for this cache entry
    ttl: Duration,
}

impl CachedJwks {
    /// Check if this cache entry is expired
    fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.cached_at)
            .map(|elapsed| elapsed > self.ttl)
            .unwrap_or(true)
    }

    /// Find a key by kid
    fn find_key(&self, kid: &str) -> Option<&JsonWebKey> {
        self.jwks
            .keys
            .iter()
            .find(|key| key.kid.as_ref().map(|k| k == kid).unwrap_or(false))
    }
}

/// JWT configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Local JWKS file path (takes priority)
    pub jwks_file: Option<String>,
    /// Remote JWKS URL (fallback)
    pub jwks_url: Option<String>,
    /// Algorithm allowlist
    pub algo_allowlist: Vec<JwtAlgorithm>,
    /// JWKS cache TTL
    pub ttl: Duration,
    /// Clock skew tolerance
    pub skew: Duration,
    /// HMAC secret (only for HS256)
    pub hmac_secret: Option<String>,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            jwks_file: None,
            jwks_url: None,
            algo_allowlist: vec![JwtAlgorithm::RS256, JwtAlgorithm::ES256],
            ttl: Duration::from_secs(3600), // 1 hour
            skew: Duration::from_secs(60),  // 1 minute
            hmac_secret: None,
        }
    }
}

/// JWT authentication provider with JWKS support
#[derive(Debug)]
pub struct JwtProvider {
    /// Configuration
    config: JwtConfig,
    /// JWKS cache
    jwks_cache: Arc<RwLock<Option<CachedJwks>>>,
    /// HTTP client for fetching JWKS
    #[cfg(feature = "jwt")]
    http_client: reqwest::Client,
}

impl Clone for JwtProvider {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            jwks_cache: self.jwks_cache.clone(),
            #[cfg(feature = "jwt")]
            http_client: reqwest::Client::new(),
        }
    }
}

impl JwtProvider {
    /// Create a new JWT provider
    pub fn new(config: JwtConfig) -> Result<Self, AuthError> {
        // Validate configuration
        if config.algo_allowlist.is_empty() {
            return Err(AuthError::internal("Algorithm allowlist cannot be empty"));
        }

        // If HS256 is allowed, require HMAC secret
        if config.algo_allowlist.contains(&JwtAlgorithm::HS256) && config.hmac_secret.is_none() {
            return Err(AuthError::internal(
                "HMAC secret required when HS256 is allowed",
            ));
        }

        // Require either file or URL
        if config.jwks_file.is_none() && config.jwks_url.is_none() {
            return Err(AuthError::internal(
                "Either jwks_file or jwks_url must be specified",
            ));
        }

        #[cfg(feature = "jwt")]
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| AuthError::internal(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            jwks_cache: Arc::new(RwLock::new(None)),
            #[cfg(feature = "jwt")]
            http_client,
        })
    }

    /// Extract JWT token from Authorization header
    pub fn extract_token(&self, auth_header: &str) -> Result<String, AuthError> {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            let token = token.trim();
            if token.is_empty() {
                return Err(AuthError::invalid("JWT token cannot be empty"));
            }
            Ok(token.to_string())
        } else {
            Err(AuthError::invalid(
                "JWT token must be provided as Bearer token",
            ))
        }
    }

    /// Load JWKS from file
    #[cfg(feature = "jwt")]
    async fn load_jwks_from_file(&self, path: &str) -> Result<JwksResponse, AuthError> {
        let content = tokio::fs::read_to_string(path).await.map_err(|e| {
            AuthError::internal(format!("Failed to read JWKS file {}: {}", path, e))
        })?;

        serde_json::from_str(&content)
            .map_err(|e| AuthError::internal(format!("Invalid JWKS format in {}: {}", path, e)))
    }

    /// Fetch JWKS from URL
    #[cfg(feature = "jwt")]
    async fn fetch_jwks_from_url(&self, url: &str) -> Result<JwksResponse, AuthError> {
        let response = self.http_client.get(url).send().await.map_err(|e| {
            AuthError::internal(format!("Failed to fetch JWKS from {}: {}", url, e))
        })?;

        if !response.status().is_success() {
            return Err(AuthError::internal(format!(
                "JWKS fetch failed with status {}: {}",
                response.status(),
                url
            )));
        }

        let jwks: JwksResponse = response.json().await.map_err(|e| {
            AuthError::internal(format!("Invalid JWKS response from {}: {}", url, e))
        })?;

        Ok(jwks)
    }

    /// Get or refresh JWKS
    #[cfg(feature = "jwt")]
    async fn get_jwks(&self) -> Result<CachedJwks, AuthError> {
        // Check cache first
        {
            let cache = self.jwks_cache.read();
            if let Some(cached) = cache.as_ref() {
                if !cached.is_expired() {
                    return Ok(cached.clone());
                }
            }
        }

        // Try to load/fetch fresh JWKS
        let jwks_result = if let Some(file_path) = &self.config.jwks_file {
            // Prefer local file
            self.load_jwks_from_file(file_path).await
        } else if let Some(url) = &self.config.jwks_url {
            // Fallback to URL
            self.fetch_jwks_from_url(url).await
        } else {
            return Err(AuthError::internal("No JWKS source configured"));
        };

        match jwks_result {
            Ok(jwks) => {
                let cached = CachedJwks {
                    jwks,
                    cached_at: SystemTime::now(),
                    ttl: self.config.ttl,
                };

                // Update cache
                {
                    let mut cache = self.jwks_cache.write();
                    *cache = Some(cached.clone());
                }

                Ok(cached)
            }
            Err(e) => {
                // If fetch failed, try to use stale cache as fallback
                let cache = self.jwks_cache.read();
                if let Some(cached) = cache.as_ref() {
                    tracing::warn!("JWKS fetch failed, using stale cache: {}", e.message());
                    Ok(cached.clone())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Convert JWK to DecodingKey
    #[cfg(feature = "jwt")]
    fn jwk_to_decoding_key(
        &self,
        jwk: &JsonWebKey,
        algorithm: &JwtAlgorithm,
    ) -> Result<DecodingKey, AuthError> {
        match algorithm {
            JwtAlgorithm::RS256 => {
                let n = jwk
                    .n
                    .as_ref()
                    .ok_or_else(|| AuthError::internal("Missing 'n' in RSA key"))?;
                let e = jwk
                    .e
                    .as_ref()
                    .ok_or_else(|| AuthError::internal("Missing 'e' in RSA key"))?;

                // Decode base64url
                let n_bytes = URL_SAFE_NO_PAD.decode(n).map_err(|e| {
                    AuthError::internal(format!("Invalid base64 in RSA modulus: {}", e))
                })?;
                let e_bytes = URL_SAFE_NO_PAD.decode(e).map_err(|e| {
                    AuthError::internal(format!("Invalid base64 in RSA exponent: {}", e))
                })?;

                // Build RSA public key
                let public_key = rsa::RsaPublicKey::new(
                    rsa::BigUint::from_bytes_be(&n_bytes),
                    rsa::BigUint::from_bytes_be(&e_bytes),
                )
                .map_err(|e| AuthError::internal(format!("Invalid RSA key: {}", e)))?;

                let pem = public_key
                    .to_pkcs1_pem(pkcs1::LineEnding::LF)
                    .map_err(|e| AuthError::internal(format!("Failed to encode RSA key: {}", e)))?;

                DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| {
                    AuthError::internal(format!("Failed to create RSA decoding key: {}", e))
                })
            }
            JwtAlgorithm::ES256 => {
                let x = jwk
                    .x
                    .as_ref()
                    .ok_or_else(|| AuthError::internal("Missing 'x' in EC key"))?;
                let y = jwk
                    .y
                    .as_ref()
                    .ok_or_else(|| AuthError::internal("Missing 'y' in EC key"))?;

                // Decode base64url
                let x_bytes = URL_SAFE_NO_PAD.decode(x).map_err(|e| {
                    AuthError::internal(format!("Invalid base64 in EC x coordinate: {}", e))
                })?;
                let y_bytes = URL_SAFE_NO_PAD.decode(y).map_err(|e| {
                    AuthError::internal(format!("Invalid base64 in EC y coordinate: {}", e))
                })?;

                // Build P-256 public key
                if x_bytes.len() != 32 || y_bytes.len() != 32 {
                    return Err(AuthError::internal("Invalid coordinate length for P-256"));
                }

                let mut x_array = [0u8; 32];
                let mut y_array = [0u8; 32];
                x_array.copy_from_slice(&x_bytes);
                y_array.copy_from_slice(&y_bytes);

                let point = p256::EncodedPoint::from_affine_coordinates(
                    &x_array.into(),
                    &y_array.into(),
                    false, // not compressed
                );

                let public_key_option = p256::PublicKey::from_encoded_point(&point);
                let public_key = if public_key_option.is_some().into() {
                    public_key_option.unwrap()
                } else {
                    return Err(AuthError::internal("Invalid EC key"));
                };

                let pem = public_key
                    .to_public_key_pem(pkcs8::LineEnding::LF)
                    .map_err(|e| AuthError::internal(format!("Failed to encode EC key: {}", e)))?;

                DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| {
                    AuthError::internal(format!("Failed to create EC decoding key: {}", e))
                })
            }
            JwtAlgorithm::HS256 => {
                let secret =
                    self.config.hmac_secret.as_ref().ok_or_else(|| {
                        AuthError::internal("HMAC secret not configured for HS256")
                    })?;
                Ok(DecodingKey::from_secret(secret.as_bytes()))
            }
        }
    }

    /// Verify JWT token
    #[cfg(feature = "jwt")]
    async fn verify_token(&self, token: &str) -> Result<(), AuthError> {
        // Decode header to get algorithm and kid
        let header = decode_header(token).map_err(|_| AuthError::invalid("Invalid JWT header"))?;

        // Check algorithm allowlist
        let alg_str = format!("{:?}", header.alg);
        let algorithm = JwtAlgorithm::from_str(&alg_str)?;

        if !self.config.algo_allowlist.contains(&algorithm) {
            return Err(AuthError::invalid(format!(
                "Algorithm {} not allowed",
                alg_str
            )));
        }

        // Setup validation
        let mut validation = Validation::new(algorithm.to_jsonwebtoken_algorithm());
        validation.leeway = self.config.skew.as_secs();
        validation.validate_exp = true;
        validation.validate_nbf = true;

        // Get decoding key
        let decoding_key = match algorithm {
            JwtAlgorithm::HS256 => {
                // Use HMAC secret directly
                self.jwk_to_decoding_key(
                    &JsonWebKey {
                        kty: "oct".to_string(),
                        kid: None,
                        alg: None,
                        n: None,
                        e: None,
                        crv: None,
                        x: None,
                        y: None,
                    },
                    &algorithm,
                )?
            }
            JwtAlgorithm::RS256 | JwtAlgorithm::ES256 => {
                // Need to find key from JWKS
                let kid = header
                    .kid
                    .ok_or_else(|| AuthError::invalid("Missing 'kid' in JWT header"))?;

                let jwks = self.get_jwks().await?;
                let jwk = jwks.find_key(&kid).ok_or_else(|| {
                    AuthError::invalid(format!("Key '{}' not found in JWKS", kid))
                })?;

                self.jwk_to_decoding_key(jwk, &algorithm)?
            }
        };

        // Verify token
        let _token_data: TokenData<serde_json::Value> = decode(token, &decoding_key, &validation)
            .map_err(|e| match &e.kind() {
            JwtErrorKind::ExpiredSignature => AuthError::invalid("JWT token has expired"),
            JwtErrorKind::ImmatureSignature => AuthError::invalid("JWT token is not yet valid"),
            JwtErrorKind::InvalidSignature => {
                AuthError::invalid("JWT signature verification failed")
            }
            JwtErrorKind::InvalidToken => AuthError::invalid("JWT token is malformed"),
            _ => {
                // Log internal errors but don't expose details
                tracing::error!("JWT verification error: {}", e);
                AuthError::invalid("JWT token verification failed")
            }
        })?;

        Ok(())
    }

    /// Verify JWT token (fallback when JWT feature is disabled)
    #[cfg(not(feature = "jwt"))]
    async fn verify_token(&self, _token: &str) -> Result<(), AuthError> {
        Err(AuthError::internal(
            "JWT support not compiled (feature 'jwt' required)",
        ))
    }
}

impl AuthProvider for JwtProvider {
    fn check(&self, headers: &HashMap<String, String>, _path: &str) -> Result<(), AuthError> {
        let auth_header = headers.get("authorization").ok_or_else(|| {
            AuthError::missing("Authorization header required for JWT authentication")
        })?;

        let token = self.extract_token(auth_header.trim())?;

        // Since we're in a sync context, we need to use a runtime
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| AuthError::internal(format!("Failed to create async runtime: {}", e)))?;

        rt.block_on(self.verify_token(&token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_algorithm_parsing() {
        assert_eq!(
            JwtAlgorithm::from_str("RS256").unwrap(),
            JwtAlgorithm::RS256
        );
        assert_eq!(
            JwtAlgorithm::from_str("ES256").unwrap(),
            JwtAlgorithm::ES256
        );
        assert_eq!(
            JwtAlgorithm::from_str("HS256").unwrap(),
            JwtAlgorithm::HS256
        );

        // Case insensitive
        assert_eq!(
            JwtAlgorithm::from_str("rs256").unwrap(),
            JwtAlgorithm::RS256
        );

        // Reject unsafe algorithms
        assert!(JwtAlgorithm::from_str("none").is_err());
        assert!(JwtAlgorithm::from_str("NULL").is_err());
        assert!(JwtAlgorithm::from_str("").is_err());
        assert!(JwtAlgorithm::from_str("UNKNOWN").is_err());
    }

    #[test]
    fn test_jwt_config_validation() {
        // Empty allowlist should fail
        let mut config = JwtConfig::default();
        config.algo_allowlist.clear();
        assert!(JwtProvider::new(config).is_err());

        // HS256 without secret should fail
        let mut config = JwtConfig::default();
        config.algo_allowlist = vec![JwtAlgorithm::HS256];
        config.hmac_secret = None;
        assert!(JwtProvider::new(config).is_err());

        // No JWKS source should fail
        let mut config = JwtConfig::default();
        config.jwks_file = None;
        config.jwks_url = None;
        assert!(JwtProvider::new(config).is_err());

        // Valid config should succeed
        let mut config = JwtConfig::default();
        config.jwks_url = Some("https://example.com/.well-known/jwks.json".to_string());
        assert!(JwtProvider::new(config).is_ok());
    }

    #[test]
    fn test_token_extraction() {
        let config = JwtConfig {
            jwks_url: Some("https://example.com/.well-known/jwks.json".to_string()),
            ..Default::default()
        };
        let provider = JwtProvider::new(config).unwrap();

        // Valid Bearer token
        let token = provider.extract_token("Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9");
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9");

        // Bearer with whitespace
        let token = provider.extract_token("Bearer   eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9   ");
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9");

        // Empty token
        let token = provider.extract_token("Bearer ");
        assert!(token.is_err());
        assert!(token.unwrap_err().message().contains("cannot be empty"));

        // Invalid format
        let token = provider.extract_token("Basic dXNlcjpwYXNz");
        assert!(token.is_err());
        assert!(token.unwrap_err().message().contains("Bearer token"));
    }

    #[test]
    fn test_cached_jwks_expiry() {
        let jwks = JwksResponse { keys: vec![] };
        let ttl = Duration::from_millis(100);

        let cached = CachedJwks {
            jwks,
            cached_at: SystemTime::now(),
            ttl,
        };

        // Should not be expired immediately
        assert!(!cached.is_expired());

        // Wait and check again
        std::thread::sleep(Duration::from_millis(150));
        assert!(cached.is_expired());
    }

    #[test]
    fn test_jwks_key_lookup() {
        let jwks = JwksResponse {
            keys: vec![
                JsonWebKey {
                    kty: "RSA".to_string(),
                    kid: Some("key1".to_string()),
                    alg: Some("RS256".to_string()),
                    n: Some("test".to_string()),
                    e: Some("AQAB".to_string()),
                    crv: None,
                    x: None,
                    y: None,
                },
                JsonWebKey {
                    kty: "EC".to_string(),
                    kid: Some("key2".to_string()),
                    alg: Some("ES256".to_string()),
                    n: None,
                    e: None,
                    crv: Some("P-256".to_string()),
                    x: Some("test_x".to_string()),
                    y: Some("test_y".to_string()),
                },
            ],
        };

        let cached = CachedJwks {
            jwks,
            cached_at: SystemTime::now(),
            ttl: Duration::from_secs(3600),
        };

        // Should find existing keys
        assert!(cached.find_key("key1").is_some());
        assert!(cached.find_key("key2").is_some());

        // Should not find non-existent key
        assert!(cached.find_key("key3").is_none());
    }
}
