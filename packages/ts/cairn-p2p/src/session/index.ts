// Session module — state machine, backoff, heartbeat, network monitor, message queue

export type {
  ConnectionState,
  StateChangedEvent,
  StateChangedListener,
  SessionStateMachineEvents,
} from './state-machine.js';
export { SessionStateMachine, isValidTransition } from './state-machine.js';

export type { BackoffConfig } from './backoff.js';
export { ExponentialBackoff, defaultBackoffConfig } from './backoff.js';

export type { HeartbeatConfig } from './heartbeat.js';
export {
  HeartbeatMonitor,
  defaultHeartbeatConfig,
  aggressiveHeartbeatConfig,
  relaxedHeartbeatConfig,
} from './heartbeat.js';

export type { NetworkChange, NetworkChangeListener } from './network-monitor.js';
export { NetworkMonitor } from './network-monitor.js';

export type { QueueStrategy, QueueConfig, QueuedMessage, EnqueueResult } from './message-queue.js';
export { MessageQueue, defaultQueueConfig } from './message-queue.js';
