"""Tests for key storage backends (in-memory and filesystem)."""

import tempfile

import pytest

from cairn.crypto.storage import (
    FilesystemKeyStorage,
    InMemoryKeyStorage,
    KeyStorage,
)

# ---------------------------------------------------------------------------
# InMemoryKeyStorage
# ---------------------------------------------------------------------------


class TestInMemoryKeyStorage:
    def test_store_and_load(self):
        store = InMemoryKeyStorage()
        store.store("test-key", b"secret data")
        assert store.load("test-key") == b"secret data"

    def test_load_nonexistent(self):
        store = InMemoryKeyStorage()
        assert store.load("missing") is None

    def test_exists(self):
        store = InMemoryKeyStorage()
        assert not store.exists("key1")
        store.store("key1", b"data")
        assert store.exists("key1")

    def test_delete(self):
        store = InMemoryKeyStorage()
        store.store("key1", b"data")
        assert store.delete("key1") is True
        assert store.load("key1") is None

    def test_delete_nonexistent(self):
        store = InMemoryKeyStorage()
        assert store.delete("nonexistent") is False

    def test_overwrite(self):
        store = InMemoryKeyStorage()
        store.store("key1", b"first")
        store.store("key1", b"second")
        assert store.load("key1") == b"second"

    def test_empty_key_id_rejected(self):
        store = InMemoryKeyStorage()
        with pytest.raises(ValueError, match="empty"):
            store.store("", b"data")

    def test_list_keys(self):
        store = InMemoryKeyStorage()
        store.store("a", b"1")
        store.store("b", b"2")
        store.store("c", b"3")
        keys = store.list_keys()
        assert sorted(keys) == ["a", "b", "c"]

    def test_list_keys_empty(self):
        store = InMemoryKeyStorage()
        assert store.list_keys() == []

    def test_data_lost_on_drop(self):
        store = InMemoryKeyStorage()
        store.store("key", b"data")
        del store
        store2 = InMemoryKeyStorage()
        assert store2.load("key") is None

    def test_implements_abc(self):
        store = InMemoryKeyStorage()
        assert isinstance(store, KeyStorage)


# ---------------------------------------------------------------------------
# FilesystemKeyStorage
# ---------------------------------------------------------------------------


class TestFilesystemKeyStorage:
    def test_store_and_load(self):
        with tempfile.TemporaryDirectory() as d:
            store = FilesystemKeyStorage(d, "passphrase")
            store.store("identity-key", b"ed25519 secret")
            assert store.load("identity-key") == b"ed25519 secret"

    def test_load_nonexistent(self):
        with tempfile.TemporaryDirectory() as d:
            store = FilesystemKeyStorage(d, "pass")
            assert store.load("nonexistent") is None

    def test_exists(self):
        with tempfile.TemporaryDirectory() as d:
            store = FilesystemKeyStorage(d, "pass")
            assert not store.exists("k")
            store.store("k", b"v")
            assert store.exists("k")

    def test_delete(self):
        with tempfile.TemporaryDirectory() as d:
            store = FilesystemKeyStorage(d, "pass")
            store.store("k", b"v")
            assert store.delete("k") is True
            assert store.load("k") is None

    def test_delete_nonexistent(self):
        with tempfile.TemporaryDirectory() as d:
            store = FilesystemKeyStorage(d, "pass")
            assert store.delete("nonexistent") is False

    def test_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            store = FilesystemKeyStorage(d, "pass")
            store.store("k", b"first")
            store.store("k", b"second")
            assert store.load("k") == b"second"

    def test_empty_key_id_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            store = FilesystemKeyStorage(d, "pass")
            with pytest.raises(ValueError, match="empty"):
                store.store("", b"data")

    def test_wrong_passphrase_rejects(self):
        with tempfile.TemporaryDirectory() as d:
            store1 = FilesystemKeyStorage(d, "correct")
            store1.store("secret", b"important data")

            # Open with wrong passphrase -- same salt, different derived key
            store2 = FilesystemKeyStorage(d, "wrong")
            assert store2.load("secret") is None

    def test_salt_persists_across_opens(self):
        with tempfile.TemporaryDirectory() as d:
            store1 = FilesystemKeyStorage(d, "pass")
            store1.store("key", b"persistent data")
            del store1

            store2 = FilesystemKeyStorage(d, "pass")
            assert store2.load("key") == b"persistent data"

    def test_empty_data_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            store = FilesystemKeyStorage(d, "pass")
            store.store("empty", b"")
            assert store.load("empty") == b""

    def test_large_data_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            store = FilesystemKeyStorage(d, "pass")
            large = bytes(range(256)) * 400  # 100KB
            store.store("large", large)
            assert store.load("large") == large

    def test_list_keys(self):
        with tempfile.TemporaryDirectory() as d:
            store = FilesystemKeyStorage(d, "pass")
            store.store("alpha", b"1")
            store.store("beta", b"2")
            keys = store.list_keys()
            assert sorted(keys) == ["alpha", "beta"]

    def test_list_keys_empty(self):
        with tempfile.TemporaryDirectory() as d:
            store = FilesystemKeyStorage(d, "pass")
            assert store.list_keys() == []

    def test_creates_directory_if_missing(self):
        with tempfile.TemporaryDirectory() as d:
            subdir = f"{d}/nested/deep/keystore"
            store = FilesystemKeyStorage(subdir, "pass")
            store.store("key", b"data")
            assert store.load("key") == b"data"

    def test_implements_abc(self):
        with tempfile.TemporaryDirectory() as d:
            store = FilesystemKeyStorage(d, "pass")
            assert isinstance(store, KeyStorage)


# ---------------------------------------------------------------------------
# ABC
# ---------------------------------------------------------------------------


class TestKeyStorageABC:
    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            KeyStorage()
