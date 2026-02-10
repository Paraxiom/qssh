//! ETSI QKD Client Integration for QSSH
//! 
//! This module provides integration with real QKD hardware devices
//! using the ETSI GS QKD 014 standard API

use crate::{Result, QsshError};
use reqwest::{Certificate, Client};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// QKD Key Response from ETSI API
#[derive(Debug, Serialize, Deserialize)]
pub struct EtsiKeyResponse {
    pub key_id: String,
    pub key: Option<String>,  // Base64-encoded key
    pub key_size: usize,
    pub qber: f32,
    pub timestamp: u64,
}

/// ETSI QKD Client for real hardware devices
pub struct EtsiQkdClient {
    client: Client,
    base_url: String,
    device_type: String,
}

impl EtsiQkdClient {
    /// Create a new ETSI QKD client with certificate authentication
    pub fn new(
        endpoint: &str,
        cert_path: &Path,
        key_path: &Path,
        ca_path: Option<&Path>,
    ) -> Result<Self> {
        log::info!("Creating ETSI QKD client for endpoint: {}", endpoint);

        let mut client_builder = Client::builder();

        // Load client certificate and key
        if cert_path.exists() {
            // Check if it's a PKCS#12 file (.p12)
            if cert_path.extension().and_then(|s| s.to_str()) == Some("p12") {
                log::info!("Loading PKCS#12 certificate from {:?}", cert_path);
                let pkcs12_data = fs::read(cert_path)
                    .map_err(|e| QsshError::Qkd(format!("Failed to read PKCS#12: {}", e)))?;

                // Get PKCS#12 password from environment variable
                let password = std::env::var("QSSH_PKCS12_PASSWORD")
                    .unwrap_or_default();

                match reqwest::Identity::from_pkcs12_der(&pkcs12_data, &password) {
                    Ok(identity) => {
                        log::info!("Successfully loaded PKCS#12 certificate");
                        client_builder = client_builder.identity(identity);
                    }
                    Err(e) => {
                        return Err(QsshError::Qkd(format!(
                            "Failed to load PKCS#12 certificate. Set QSSH_PKCS12_PASSWORD environment variable. Error: {}", e
                        )));
                    }
                }
            } else if key_path.exists() {
                // Load separate cert and key files
                log::info!("Loading client certificate from {:?}", cert_path);
                let cert_data = fs::read(cert_path)
                    .map_err(|e| QsshError::Qkd(format!("Failed to read certificate: {}", e)))?;
                
                let key_data = fs::read(key_path)
                    .map_err(|e| QsshError::Qkd(format!("Failed to read key: {}", e)))?;

                log::info!("Creating identity from certificate and key");
                let identity = reqwest::Identity::from_pkcs8_pem(&cert_data, &key_data)
                    .map_err(|e| QsshError::Qkd(format!("Failed to create identity: {}", e)))?;
                
                client_builder = client_builder.identity(identity);
            }
        }

        // Load CA certificate if provided
        if let Some(ca) = ca_path {
            if ca.exists() {
                log::info!("Loading CA certificate from {:?}", ca);
                let ca_data = fs::read(ca)
                    .map_err(|e| QsshError::Qkd(format!("Failed to read CA cert: {}", e)))?;
                let ca_cert = Certificate::from_pem(&ca_data)
                    .map_err(|e| QsshError::Qkd(format!("Invalid CA certificate: {}", e)))?;
                client_builder = client_builder.add_root_certificate(ca_cert);
            }
        }

        // Only accept invalid certs if explicitly opted in (for lab/testing with self-signed certs)
        if std::env::var("QSSH_ALLOW_INSECURE_TLS").as_deref() == Ok("1") {
            log::warn!("TLS certificate validation DISABLED via QSSH_ALLOW_INSECURE_TLS");
            client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        let client = client_builder.build()
            .map_err(|e| QsshError::Qkd(format!("Failed to build HTTP client: {}", e)))?;

        // Determine device type from environment or default to unknown
        let device_type = std::env::var("QSSH_QKD_DEVICE_TYPE")
            .unwrap_or_else(|_| "unknown".to_string());

        Ok(Self {
            client,
            base_url: endpoint.to_string(),
            device_type,
        })
    }

    /// Request a new quantum key
    pub async fn get_key(&self, size_bytes: usize) -> Result<Vec<u8>> {
        log::info!("Requesting {} byte key from {} device", size_bytes, self.device_type);

        // Build the request based on device type
        let url = format!("{}/keys/enc_keys", self.base_url);
        
        #[derive(Serialize)]
        struct KeyRequest {
            size: usize,
            #[serde(rename = "SAE_ID")]
            sae_id: String,
        }

        let request = KeyRequest {
            size: size_bytes,
            sae_id: "qssh-session".to_string(),
        };

        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| QsshError::Qkd(format!("Failed to request key: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            log::error!("QKD API error {}: {}", status, error_text);
            return Err(QsshError::Qkd(format!("QKD API request failed (status {})", status)));
        }

        let key_response: EtsiKeyResponse = response.json().await
            .map_err(|e| QsshError::Qkd(format!("Failed to parse key response: {}", e)))?;

        // Decode the base64 key
        if let Some(key_b64) = key_response.key {
            let key_bytes = base64::decode(&key_b64)
                .map_err(|e| QsshError::Qkd(format!("Failed to decode key: {}", e)))?;
            
            log::info!("Successfully retrieved key: {} (QBER: {})", 
                key_response.key_id, key_response.qber);
            
            Ok(key_bytes)
        } else {
            Err(QsshError::Qkd("No key material in response".into()))
        }
    }

    /// Get QKD link status
    pub async fn get_status(&self) -> Result<QkdStatus> {
        let url = format!("{}/status", self.base_url);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| QsshError::Qkd(format!("Failed to get status: {}", e)))?;

        if !response.status().is_success() {
            return Err(QsshError::Qkd("Failed to get QKD status".into()));
        }

        let status: QkdStatus = response.json().await
            .map_err(|e| QsshError::Qkd(format!("Failed to parse status: {}", e)))?;

        Ok(status)
    }
}

/// QKD Link Status
#[derive(Debug, Serialize, Deserialize)]
pub struct QkdStatus {
    pub link_status: String,
    pub key_rate: f64,
    pub qber: f32,
    pub available_keys: usize,
}

/// Create an ETSI QKD client from configuration
pub fn create_etsi_client(config: &super::QkdConfig) -> Result<EtsiQkdClient> {
    let cert_path = config.cert_path.as_ref()
        .ok_or_else(|| QsshError::Qkd("Certificate path not configured".into()))?;
    
    let key_path = config.key_path.as_ref()
        .ok_or_else(|| QsshError::Qkd("Key path not configured".into()))?;
    
    let ca_path = config.ca_path.as_ref().map(|s| Path::new(s));
    
    let endpoint = std::env::var("QSSH_QKD_ENDPOINT")
        .map_err(|_| QsshError::Qkd("QKD endpoint not configured. Set QSSH_QKD_ENDPOINT env var".into()))?;

    EtsiQkdClient::new(
        &endpoint,
        Path::new(cert_path),
        Path::new(key_path),
        ca_path,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qkd_config() {
        let config = super::super::QkdConfig {
            cert_path: Some("/path/to/cert.pem".to_string()),
            key_path: Some("/path/to/key.pem".to_string()),
            ca_path: Some("/path/to/ca.pem".to_string()),
            timeout_ms: 5000,
            cache_size: 10,
            min_entropy: 0.9,
        };

        assert!(config.cert_path.is_some());
    }
}