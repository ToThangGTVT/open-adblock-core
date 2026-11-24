package io.github.tothanggtvt.openadblock.core;

/**
 * Receives batched query-log and statistics JSON, at most every five seconds, when a batch fills
 * up, and once more when the tunnel stops. See {@code docs/API.md#events} for the schema.
 *
 * <p>Called on an engine thread: hand the string to your own executor and return.
 */
@FunctionalInterface
public interface EngineEventListener {
    void onEvents(String json);
}
