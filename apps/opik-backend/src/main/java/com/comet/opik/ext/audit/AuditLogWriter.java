package com.comet.opik.ext.audit;

import com.comet.opik.infrastructure.OpikConfiguration;
import io.dropwizard.lifecycle.Managed;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.metrics.LongCounter;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Bounded in-memory queue flushed to ClickHouse in batches. Never blocks or fails the request path: when the queue is
 * full the event is dropped and counted ({@code opik.audit.dropped}). Best-effort flush on shutdown.
 */
@Slf4j
@Singleton
public class AuditLogWriter implements Managed {

    private final AuditConfig config;
    private final AuditLogDAO dao;
    private final BlockingQueue<AuditEvent> queue;
    private final LongCounter dropped;
    private ScheduledExecutorService executor;

    @Inject
    public AuditLogWriter(@NonNull OpikConfiguration configuration, @NonNull AuditLogDAO dao) {
        this.config = configuration.getAudit();
        this.dao = dao;
        this.queue = new ArrayBlockingQueue<>(Math.max(100, config.getQueueCapacity()));
        this.dropped = GlobalOpenTelemetry.get().getMeter("opik.audit").counterBuilder("opik.audit.dropped")
                .setDescription("Audit events dropped because the queue was full").build();
    }

    public boolean isEnabled() {
        return config.isEnabled();
    }

    public void offer(AuditEvent event) {
        if (!config.isEnabled()) {
            return;
        }
        if (!queue.offer(event)) {
            dropped.add(1);
            log.warn("Audit queue full, dropping event '{}'", event.action());
        }
    }

    @Override
    public void start() {
        if (!config.isEnabled()) {
            return;
        }
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            var thread = new Thread(r, "audit-log-writer");
            thread.setDaemon(true);
            return thread;
        });
        long interval = Math.max(100, config.getFlushInterval().toMilliseconds());
        executor.scheduleWithFixedDelay(this::flushAll, interval, interval, TimeUnit.MILLISECONDS);
        log.info("Audit log writer started (flush every {}ms)", interval);
    }

    @Override
    public void stop() {
        if (executor != null) {
            executor.shutdown();
            flushAll();
        }
    }

    void flushAll() {
        try {
            while (!queue.isEmpty()) {
                List<AuditEvent> batch = new ArrayList<>(config.getBatchSize());
                queue.drainTo(batch, config.getBatchSize());
                if (batch.isEmpty()) {
                    return;
                }
                try {
                    dao.insert(batch).block(Duration.ofSeconds(30));
                } catch (RuntimeException e) {
                    log.warn("Failed to write {} audit events, dropping them", batch.size(), e);
                    dropped.add(batch.size());
                    return;
                }
            }
        } catch (RuntimeException e) {
            log.warn("Audit flush failed", e);
        }
    }
}
