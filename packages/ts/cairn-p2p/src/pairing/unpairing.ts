/** Event emitted when a peer is unpaired (local or remote initiated). */
export type UnpairingEvent =
  | { type: 'local_unpair_completed'; peerId: Uint8Array }
  | { type: 'remote_peer_unpaired'; peerId: Uint8Array };

/**
 * Execute the local unpairing protocol for a given peer.
 *
 * Steps:
 * 1. Verify the peer exists in the paired peers set.
 * 2. Remove the peer from the set.
 * 3. Return LocalUnpairCompleted event.
 *
 * Note: sending PairRevoke (0x0105) and closing sessions is delegated to the
 * session management layer. This function handles only state cleanup.
 *
 * @param peerId - the peer to unpair
 * @param isPaired - function to check if peer is currently paired
 * @param removePeer - function to remove peer state
 */
export function unpair(
  peerId: Uint8Array,
  isPaired: (id: Uint8Array) => boolean,
  removePeer: (id: Uint8Array) => boolean,
): UnpairingEvent {
  if (!isPaired(peerId)) {
    throw new Error(`peer not found in trust store`);
  }

  const removed = removePeer(peerId);
  if (!removed) {
    throw new Error('peer was present but removal returned false');
  }

  return { type: 'local_unpair_completed', peerId };
}

/**
 * Handle an incoming PairRevoke message from a remote peer.
 *
 * Removes the peer from local state (if present) and returns
 * a RemotePeerUnpaired event.
 */
export function handlePairRevoke(
  peerId: Uint8Array,
  removePeer: (id: Uint8Array) => boolean,
): UnpairingEvent {
  removePeer(peerId);
  return { type: 'remote_peer_unpaired', peerId };
}
