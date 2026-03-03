/**
 * Sync protocol types and utilities for chunked file transfer,
 * conflict detection, and delta synchronization.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

/** Default chunk size: 64 KB */
const DEFAULT_CHUNK_SIZE = 65536;

/** Rolling hash window size for delta sync */
const ROLLING_HASH_WINDOW = 64;

/** Metadata for a file in the sync directory. */
export interface FileMeta {
  path: string;
  size: number;
  modified: number;
  hash: string;
  peer_id_prefix: string;
}

/** A chunk of file data for transfer. */
export interface ChunkData {
  file_path: string;
  file_hash: string;
  chunk_index: number;
  chunk_count: number;
  chunk_data: string; // base64
}

/** A delta block for bandwidth-efficient updates. */
export interface DeltaBlock {
  offset: number;
  length: number;
  data: string; // base64
}

/**
 * Sync engine managing file state, chunked transfer, conflict resolution,
 * and delta synchronization.
 */
export class SyncEngine {
  private syncDir: string;
  private chunkSize: number;
  private files: Map<string, FileMeta> = new Map();
  private chunkProgress: Map<string, number> = new Map();

  constructor(syncDir: string, chunkSize: number = DEFAULT_CHUNK_SIZE) {
    this.syncDir = syncDir;
    this.chunkSize = chunkSize;
  }

  /** Scan the sync directory and compute metadata for all files. */
  scanDirectory(): FileMeta[] {
    this.files.clear();
    const result: FileMeta[] = [];
    this.scanRecursive(this.syncDir, result);
    return result;
  }

  private scanRecursive(dir: string, result: FileMeta[]): void {
    if (!fs.existsSync(dir)) return;

    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;

      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        this.scanRecursive(fullPath, result);
      } else if (entry.isFile()) {
        const meta = this.computeFileMeta(fullPath, this.syncDir);
        if (meta) {
          this.files.set(meta.path, meta);
          result.push(meta);
        }
      }
    }
  }

  /** Compute metadata for a single file. */
  computeFileMeta(filePath: string, baseDir: string): FileMeta | null {
    try {
      const stat = fs.statSync(filePath);
      if (!stat.isFile()) return null;

      const relPath = path.relative(baseDir, filePath);
      const hash = this.computeFileHash(filePath);

      return {
        path: relPath,
        size: stat.size,
        modified: Math.floor(stat.mtimeMs / 1000),
        hash,
        peer_id_prefix: '',
      };
    } catch {
      return null;
    }
  }

  /** Compute SHA-256 hash of a file. */
  private computeFileHash(filePath: string): string {
    const data = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /** Get metadata for a specific file. */
  getFileMeta(relPath: string): FileMeta | undefined {
    return this.files.get(relPath);
  }

  // -----------------------------------------------------------------------
  // Chunked Transfer
  // -----------------------------------------------------------------------

  /** Split a file into chunks for transfer. */
  splitFile(filePath: string, relPath: string): ChunkData[] {
    const data = fs.readFileSync(filePath);
    const fileHash = crypto.createHash('sha256').update(data).digest('hex');
    const chunkCount = Math.ceil(data.length / this.chunkSize);
    const chunks: ChunkData[] = [];

    for (let i = 0; i < chunkCount; i++) {
      const start = i * this.chunkSize;
      const end = Math.min(start + this.chunkSize, data.length);
      const chunkData = data.subarray(start, end);

      chunks.push({
        file_path: relPath,
        file_hash: fileHash,
        chunk_index: i,
        chunk_count: chunkCount,
        chunk_data: Buffer.from(chunkData).toString('base64'),
      });
    }

    return chunks;
  }

  /** Write a received chunk to disk. */
  writeChunk(destPath: string, chunkIndex: number, data: Buffer): void {
    const offset = chunkIndex * this.chunkSize;
    const fd = fs.openSync(destPath, fs.existsSync(destPath) ? 'r+' : 'w');
    try {
      const buf = Buffer.from(data);
      fs.writeSync(fd, buf, 0, buf.length, offset);
    } finally {
      fs.closeSync(fd);
    }
  }

  /** Get the last received chunk index for resume. */
  lastReceivedChunk(relPath: string): number {
    return this.chunkProgress.get(relPath) ?? 0;
  }

  /** Record reception of a chunk. */
  recordChunk(relPath: string, index: number): void {
    this.chunkProgress.set(relPath, index + 1);
  }

  /** Mark a file as fully received. */
  markComplete(relPath: string, hash: string): void {
    this.chunkProgress.delete(relPath);
    const meta = this.files.get(relPath);
    if (meta) {
      meta.hash = hash;
    }
  }

  // -----------------------------------------------------------------------
  // Conflict Resolution
  // -----------------------------------------------------------------------

  /**
   * Generate the conflict file path.
   * Format: file.txt.conflict.<peer_id_prefix>.<timestamp>
   */
  resolveConflictPath(relPath: string, peerIdPrefix: string, timestamp: number): string {
    const parsed = path.parse(relPath);
    const conflictName = `${parsed.base}.conflict.${peerIdPrefix || 'unknown'}.${timestamp}`;
    return path.join(parsed.dir, conflictName);
  }

  /** Preserve a conflicting version alongside the original. */
  preserveConflict(
    relPath: string,
    peerIdPrefix: string,
    timestamp: number,
    data: Buffer,
  ): string {
    const conflictPath = this.resolveConflictPath(relPath, peerIdPrefix, timestamp);
    const fullPath = path.join(this.syncDir, conflictPath);
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(fullPath, data);
    return conflictPath;
  }

  // -----------------------------------------------------------------------
  // Delta Sync
  // -----------------------------------------------------------------------

  /** Compute delta blocks between old and new versions of a file. */
  computeDelta(oldData: Buffer, newData: Buffer): DeltaBlock[] {
    const oldSigs = this.computeSignatures(oldData);
    const deltas: DeltaBlock[] = [];
    let pos = 0;
    let changeStart: number | null = null;

    while (pos + ROLLING_HASH_WINDOW <= newData.length) {
      const window = newData.subarray(pos, pos + ROLLING_HASH_WINDOW);
      const hash = rollingHash(window);

      const offsets = oldSigs.get(hash);
      if (offsets) {
        const matched = offsets.some((off) => {
          if (off + ROLLING_HASH_WINDOW > oldData.length) return false;
          return oldData.subarray(off, off + ROLLING_HASH_WINDOW).equals(window);
        });

        if (matched) {
          if (changeStart !== null) {
            deltas.push({
              offset: changeStart,
              length: pos - changeStart,
              data: newData.subarray(changeStart, pos).toString('base64'),
            });
            changeStart = null;
          }
          pos += ROLLING_HASH_WINDOW;
          continue;
        }
      }

      if (changeStart === null) {
        changeStart = pos;
      }
      pos += 1;
    }

    // Flush remaining
    if (changeStart !== null) {
      deltas.push({
        offset: changeStart,
        length: newData.length - changeStart,
        data: newData.subarray(changeStart).toString('base64'),
      });
    } else if (pos < newData.length) {
      deltas.push({
        offset: pos,
        length: newData.length - pos,
        data: newData.subarray(pos).toString('base64'),
      });
    }

    return deltas;
  }

  /** Apply delta blocks to produce the updated file. */
  applyDelta(baseData: Buffer, deltas: DeltaBlock[]): Buffer {
    const result = Buffer.from(baseData);
    for (const delta of deltas) {
      const data = Buffer.from(delta.data, 'base64');
      data.copy(result, delta.offset);
    }
    return result;
  }

  /** Compute rolling hash signatures for a buffer. */
  private computeSignatures(data: Buffer): Map<number, number[]> {
    const sigs = new Map<number, number[]>();
    if (data.length < ROLLING_HASH_WINDOW) return sigs;

    for (let offset = 0; offset <= data.length - ROLLING_HASH_WINDOW; offset++) {
      const window = data.subarray(offset, offset + ROLLING_HASH_WINDOW);
      const hash = rollingHash(window);
      const existing = sigs.get(hash);
      if (existing) {
        existing.push(offset);
      } else {
        sigs.set(hash, [offset]);
      }
    }

    return sigs;
  }
}

/** Simple rolling hash (Adler-32 variant) for delta sync. */
function rollingHash(data: Uint8Array): number {
  let a = 1;
  let b = 0;
  for (const byte of data) {
    a = (a + byte) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}
