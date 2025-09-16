// SFTP Subsystem Module
pub mod sftp;

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Trait for SSH subsystems
#[async_trait]
pub trait Subsystem: Send + Sync {
    /// Name of the subsystem (e.g., "sftp")
    fn name(&self) -> &str;

    /// Start the subsystem (simplified - not using Session for now)
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Handle incoming data
    async fn handle_data(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;

    /// Shutdown the subsystem
    async fn shutdown(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Subsystem registry
pub struct SubsystemRegistry {
    subsystems: Vec<Box<dyn Subsystem>>,
}

impl SubsystemRegistry {
    pub fn new() -> Self {
        let mut registry = SubsystemRegistry {
            subsystems: Vec::new(),
        };

        // Register SFTP by default
        registry.register(Box::new(sftp::SftpSubsystem::new()));

        registry
    }

    pub fn register(&mut self, subsystem: Box<dyn Subsystem>) {
        self.subsystems.push(subsystem);
    }

    pub fn get(&self, name: &str) -> Option<&dyn Subsystem> {
        self.subsystems
            .iter()
            .find(|s| s.name() == name)
            .map(|s| s.as_ref())
    }
}