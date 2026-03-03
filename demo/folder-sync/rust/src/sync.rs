//! Sync protocol types and utilities for chunked file transfer,
//! conflict detection, and delta synchronization.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Default chunk size: 64 KB
pub const DEFAULT_CHUNK_SIZE: usize = 65536;

/// Rolling hash window size for delta sync
const ROLLING_HASH_WINDOW: usize = 64;

// ---------------------------------------------------------------------------
// File Metadata
// ---------------------------------------------------------------------------

/// Metadata for a file in the sync directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    /// Relative path within the sync folder
    pub path: String,
    /// File size in bytes
    pub size: u64,
    /// Modification timestamp (Unix seconds)
    pub modified: u64,
    /// SHA-256 content hash (hex)
    pub hash: String,
    /// Prefix of the peer ID that owns this version
    #[serde(default)]
    pub peer_id_prefix: String,
}

/// A chunk of file data for transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkData {
    /// Relative path within the sync folder
    pub file_path: String,
    /// SHA-256 hash of the complete file
    pub file_hash: String,
    /// Zero-based chunk number
    pub chunk_index: u32,
    /// Total number of chunks
    pub chunk_count: u32,
    /// Raw bytes (base64-encoded in JSON)
    #[serde(with = "base64_bytes")]
    pub chunk_data: Vec<u8>,
}

/// A delta block for bandwidth-efficient updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaBlock {
    /// Offset in the file
    pub offset: u64,
    /// Length of the changed region
    pub length: u32,
    /// New data for this region
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Sync State
// ---------------------------------------------------------------------------

/// Tracks local file state and chunk reception progress.
pub struct SyncState {
    sync_dir: PathBuf,
    /// Known file metadata by relative path
    files: HashMap<String, FileMeta>,
    /// Last received chunk index per file path
    chunk_progress: HashMap<String, u32>,
}

impl SyncState {
    pub fn new(sync_dir: PathBuf) -> Self {
        Self {
            sync_dir,
            files: HashMap::new(),
            chunk_progress: HashMap::new(),
        }
    }

    /// Scan the sync directory and compute metadata for all files.
    pub fn scan_directory(&mut self) -> std::io::Result<Vec<FileMeta>> {
        self.files.clear();
        let mut result = Vec::new();

        if !self.sync_dir.exists() {
            return Ok(result);
        }

        self.scan_recursive(&self.sync_dir.clone(), &mut result)?;
        Ok(result)
    }

    fn scan_recursive(&mut self, dir: &Path, result: &mut Vec<FileMeta>) -> std::io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            // Skip hidden files and .cairn directories
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.') {
                    continue;
                }
            }

            if path.is_dir() {
                self.scan_recursive(&path, result)?;
            } else if path.is_file() {
                let rel_path = path
                    .strip_prefix(&self.sync_dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();

                let metadata = fs::metadata(&path)?;
                let modified = metadata
                    .modified()
                    .unwrap_or(SystemTime::UNIX_EPOCH)
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let hash = compute_file_hash(&path)?;

                let meta = FileMeta {
                    path: rel_path.clone(),
                    size: metadata.len(),
                    modified,
                    hash,
                    peer_id_prefix: String::new(),
                };

                self.files.insert(rel_path, meta.clone());
                result.push(meta);
            }
        }
        Ok(())
    }

    /// Get metadata for a specific file.
    pub fn get_file_meta(&self, path: &str) -> Option<&FileMeta> {
        self.files.get(path)
    }

    /// Get the last received chunk index for resume.
    pub fn last_received_chunk(&self, path: &str) -> u32 {
        self.chunk_progress.get(path).copied().unwrap_or(0)
    }

    /// Record reception of a chunk.
    pub fn record_chunk(&mut self, path: &str, index: u32) {
        self.chunk_progress.insert(path.to_string(), index + 1);
    }

    /// Mark a file as fully received.
    pub fn mark_complete(&mut self, path: &str, hash: &str) {
        self.chunk_progress.remove(path);
        if let Some(meta) = self.files.get_mut(path) {
            meta.hash = hash.to_string();
        }
    }
}

// ---------------------------------------------------------------------------
// Chunked Transfer
// ---------------------------------------------------------------------------

/// Handles splitting files into chunks and reassembling them.
pub struct ChunkTransfer {
    chunk_size: usize,
}

impl ChunkTransfer {
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    /// Split a file into chunks for transfer.
    pub fn split_file(&self, path: &Path) -> std::io::Result<Vec<ChunkData>> {
        let data = fs::read(path)?;
        let file_hash = compute_hash(&data);
        let file_path = path.to_string_lossy().to_string();
        let chunk_count = ((data.len() + self.chunk_size - 1) / self.chunk_size) as u32;

        let mut chunks = Vec::new();
        for (i, chunk) in data.chunks(self.chunk_size).enumerate() {
            chunks.push(ChunkData {
                file_path: file_path.clone(),
                file_hash: file_hash.clone(),
                chunk_index: i as u32,
                chunk_count,
                chunk_data: chunk.to_vec(),
            });
        }

        Ok(chunks)
    }

    /// Write a received chunk to disk.
    pub fn write_chunk(&self, dest: &Path, chunk: &ChunkData) -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(dest)?;

        let offset = chunk.chunk_index as u64 * self.chunk_size as u64;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&chunk.chunk_data)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Conflict Resolution
// ---------------------------------------------------------------------------

/// Handles file conflict detection and dual-version preservation.
pub struct ConflictResolver;

impl ConflictResolver {
    pub fn new() -> Self {
        Self
    }

    /// Generate the conflict file path.
    ///
    /// Format: `file.txt.conflict.<peer_id_prefix>.<timestamp>`
    pub fn resolve_path(
        &self,
        sync_dir: &Path,
        rel_path: &str,
        peer_id_prefix: &str,
        timestamp: u64,
    ) -> PathBuf {
        let original = sync_dir.join(rel_path);
        let conflict_name = format!(
            "{}.conflict.{}.{}",
            original.file_name().unwrap_or_default().to_string_lossy(),
            if peer_id_prefix.is_empty() {
                "unknown"
            } else {
                peer_id_prefix
            },
            timestamp
        );
        original.with_file_name(conflict_name)
    }

    /// Preserve a conflicting version alongside the original.
    pub fn preserve_conflict(
        &self,
        sync_dir: &Path,
        rel_path: &str,
        peer_id_prefix: &str,
        timestamp: u64,
        data: &[u8],
    ) -> std::io::Result<PathBuf> {
        let conflict_path = self.resolve_path(sync_dir, rel_path, peer_id_prefix, timestamp);
        if let Some(parent) = conflict_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&conflict_path, data)?;
        Ok(conflict_path)
    }
}

// ---------------------------------------------------------------------------
// Delta Sync
// ---------------------------------------------------------------------------

/// Rolling-hash based delta synchronization for bandwidth efficiency.
pub struct DeltaSync {
    window_size: usize,
}

impl DeltaSync {
    pub fn new() -> Self {
        Self {
            window_size: ROLLING_HASH_WINDOW,
        }
    }

    /// Compute the rolling hash signature for a file.
    ///
    /// Returns a map of rolling hash values to their offsets.
    pub fn compute_signatures(&self, data: &[u8]) -> HashMap<u32, Vec<u64>> {
        let mut sigs = HashMap::new();
        if data.len() < self.window_size {
            return sigs;
        }

        for offset in 0..=(data.len() - self.window_size) {
            let window = &data[offset..offset + self.window_size];
            let hash = rolling_hash(window);
            sigs.entry(hash).or_insert_with(Vec::new).push(offset as u64);
        }
        sigs
    }

    /// Compute delta blocks between old and new versions of a file.
    ///
    /// Returns only the changed regions that need to be transferred.
    pub fn compute_delta(&self, old_data: &[u8], new_data: &[u8]) -> Vec<DeltaBlock> {
        let old_sigs = self.compute_signatures(old_data);
        let mut deltas = Vec::new();
        let mut pos = 0;
        let mut change_start: Option<usize> = None;

        while pos + self.window_size <= new_data.len() {
            let window = &new_data[pos..pos + self.window_size];
            let hash = rolling_hash(window);

            if let Some(offsets) = old_sigs.get(&hash) {
                // Check for exact match
                let matched = offsets.iter().any(|&off| {
                    let off = off as usize;
                    off + self.window_size <= old_data.len()
                        && old_data[off..off + self.window_size] == *window
                });

                if matched {
                    // Flush any pending change
                    if let Some(start) = change_start.take() {
                        deltas.push(DeltaBlock {
                            offset: start as u64,
                            length: (pos - start) as u32,
                            data: new_data[start..pos].to_vec(),
                        });
                    }
                    pos += self.window_size;
                    continue;
                }
            }

            // Mark as changed
            if change_start.is_none() {
                change_start = Some(pos);
            }
            pos += 1;
        }

        // Flush remaining
        if let Some(start) = change_start {
            deltas.push(DeltaBlock {
                offset: start as u64,
                length: (new_data.len() - start) as u32,
                data: new_data[start..].to_vec(),
            });
        } else if pos < new_data.len() {
            deltas.push(DeltaBlock {
                offset: pos as u64,
                length: (new_data.len() - pos) as u32,
                data: new_data[pos..].to_vec(),
            });
        }

        deltas
    }

    /// Apply delta blocks to produce the updated file.
    pub fn apply_delta(&self, base_data: &[u8], deltas: &[DeltaBlock]) -> Vec<u8> {
        let mut result = base_data.to_vec();
        for delta in deltas {
            let offset = delta.offset as usize;
            let end = offset + delta.length as usize;

            // Extend if necessary
            if end > result.len() {
                result.resize(end, 0);
            }
            result[offset..offset + delta.data.len()].copy_from_slice(&delta.data);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute SHA-256 hash of a byte slice, returned as hex string.
pub fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute SHA-256 hash of a file on disk.
pub fn compute_file_hash(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Simple rolling hash (Adler-32 variant) for delta sync.
fn rolling_hash(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Base64 encoding/decoding for JSON serialization of binary data.
mod base64_bytes {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(data).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn compute_hash_deterministic() {
        let h1 = compute_hash(b"hello world");
        let h2 = compute_hash(b"hello world");
        assert_eq!(h1, h2);
        assert_ne!(h1, compute_hash(b"hello world!"));
    }

    #[test]
    fn chunk_split_and_write() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("source.bin");
        let dest = dir.path().join("dest.bin");

        // Create a test file larger than one chunk
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
        fs::write(&src, &data).unwrap();

        let chunker = ChunkTransfer::new(65536);
        let chunks = chunker.split_file(&src).unwrap();

        assert_eq!(chunks.len(), 4); // 200000 / 65536 = 3.05 -> 4 chunks
        assert_eq!(chunks[0].chunk_count, 4);
        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[3].chunk_index, 3);

        // Write chunks to dest
        for chunk in &chunks {
            chunker.write_chunk(&dest, chunk).unwrap();
        }

        let result = fs::read(&dest).unwrap();
        assert_eq!(&result[..data.len()], &data[..]);
    }

    #[test]
    fn conflict_path_format() {
        let resolver = ConflictResolver::new();
        let path = resolver.resolve_path(
            Path::new("/sync"),
            "docs/readme.txt",
            "abc123",
            1700000000,
        );
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.contains("conflict"));
        assert!(name.contains("abc123"));
        assert!(name.contains("1700000000"));
    }

    #[test]
    fn delta_sync_identical_files() {
        let ds = DeltaSync::new();
        let data = vec![0u8; 1000];
        let deltas = ds.compute_delta(&data, &data);
        assert!(deltas.is_empty());
    }

    #[test]
    fn delta_sync_detects_changes() {
        let ds = DeltaSync::new();
        let old = vec![0u8; 1000];
        let mut new = old.clone();
        // Modify a section
        for i in 200..300 {
            new[i] = 0xFF;
        }
        let deltas = ds.compute_delta(&old, &new);
        assert!(!deltas.is_empty());

        // Apply and verify
        let result = ds.apply_delta(&old, &deltas);
        assert_eq!(result.len(), new.len());
        assert_eq!(&result[200..300], &new[200..300]);
    }

    #[test]
    fn rolling_hash_consistency() {
        let data = b"hello world, this is a test of rolling hash";
        let h1 = rolling_hash(data);
        let h2 = rolling_hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn scan_directory_finds_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), "hello").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/b.txt"), "world").unwrap();

        let mut state = SyncState::new(dir.path().to_path_buf());
        let files = state.scan_directory().unwrap();

        assert_eq!(files.len(), 2);
    }

    #[test]
    fn sync_state_chunk_tracking() {
        let mut state = SyncState::new(PathBuf::from("/tmp/test"));
        assert_eq!(state.last_received_chunk("file.txt"), 0);

        state.record_chunk("file.txt", 0);
        assert_eq!(state.last_received_chunk("file.txt"), 1);

        state.record_chunk("file.txt", 1);
        assert_eq!(state.last_received_chunk("file.txt"), 2);

        state.mark_complete("file.txt", "abc123");
        assert_eq!(state.last_received_chunk("file.txt"), 0);
    }
}
