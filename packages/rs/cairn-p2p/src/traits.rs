use async_trait::async_trait;

use crate::error::Result;

#[async_trait]
pub trait KeyStore: Send + Sync {
    async fn store(&self, key_id: &str, data: &[u8]) -> Result<()>;
    async fn retrieve(&self, key_id: &str) -> Result<Vec<u8>>;
    async fn delete(&self, key_id: &str) -> Result<()>;
    async fn exists(&self, key_id: &str) -> Result<bool>;
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&mut self, addr: &str) -> Result<()>;
    async fn send(&mut self, data: &[u8]) -> Result<()>;
    async fn receive(&mut self) -> Result<Vec<u8>>;
    async fn close(&mut self) -> Result<()>;
}

#[async_trait]
pub trait PairingMechanism: Send + Sync {
    async fn initiate(&mut self) -> Result<Vec<u8>>;
    async fn respond(&mut self, challenge: &[u8]) -> Result<Vec<u8>>;
    async fn verify(&self, response: &[u8]) -> Result<bool>;
}

#[async_trait]
pub trait DiscoveryBackend: Send + Sync {
    async fn publish(&self, rendezvous_id: &str) -> Result<()>;
    async fn query(&self, rendezvous_id: &str) -> Result<Vec<String>>;
}
