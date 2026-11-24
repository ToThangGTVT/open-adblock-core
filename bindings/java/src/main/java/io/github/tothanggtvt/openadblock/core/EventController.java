package io.github.tothanggtvt.openadblock.core;

/**
 * Query log, statistics and request capture. Outside an explicit request capture the engine only
 * reports metadata (host, app, action, matched rule), never payloads or full URLs.
 */
public interface EventController {
    /** Replaces the listener; {@code null} detaches it. */
    void setEventListener(EngineEventListener listener);

    /** Delivers pending events now instead of at the next batch. */
    void flushEvents();

    /**
     * Records request previews (method, path, query, truncated body) of the one app the user
     * picked, for {@code minutes}, tagged with {@code session}. {@code minutes <= 0} ends capture.
     */
    void setRequestCapture(int app, long session, int minutes);
}
