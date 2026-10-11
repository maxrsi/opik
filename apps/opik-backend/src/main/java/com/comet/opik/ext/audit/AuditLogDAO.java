package com.comet.opik.ext.audit;

import com.comet.opik.utils.template.TemplateUtils;
import io.r2dbc.spi.ConnectionFactory;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/** Batch insert into the ClickHouse {@code audit_logs} table (migration 900001_create_audit_logs.sql). */
@Singleton
@RequiredArgsConstructor(onConstructor_ = @Inject)
public class AuditLogDAO {

    private static final String INSERT = """
            INSERT INTO audit_logs (id, event_time, source, workspace_id, workspace_name, actor, actor_type,
                credential_id, action, outcome, http_method, route, path, status, resource_type, resource_id,
                path_params, required_permissions, client_ip, user_agent, trace_id, duration_ms, details)
            VALUES <items:{item |
                (
                    :id<item.index>,
                    parseDateTime64BestEffort(:event_time<item.index>, 3),
                    'backend',
                    :workspace_id<item.index>,
                    :workspace_name<item.index>,
                    :actor<item.index>,
                    :actor_type<item.index>,
                    :credential_id<item.index>,
                    :action<item.index>,
                    :outcome<item.index>,
                    :http_method<item.index>,
                    :route<item.index>,
                    :path<item.index>,
                    :status<item.index>,
                    :resource_type<item.index>,
                    :resource_id<item.index>,
                    mapFromArrays(:pp_keys<item.index>, :pp_values<item.index>),
                    :required_permissions<item.index>,
                    :client_ip<item.index>,
                    :user_agent<item.index>,
                    :trace_id<item.index>,
                    :duration_ms<item.index>,
                    :details<item.index>
                )
                <if(item.hasNext)>,<endif>
            }>
            ;
            """;

    private final @NonNull ConnectionFactory connectionFactory;

    public Mono<Void> insert(@NonNull List<AuditEvent> events) {
        if (events.isEmpty()) {
            return Mono.empty();
        }
        return Mono.from(connectionFactory.create())
                .flatMapMany(connection -> {
                    var template = TemplateUtils.getBatchSql(INSERT, events.size());
                    var statement = connection.createStatement(template.render());
                    for (int i = 0; i < events.size(); i++) {
                        var e = events.get(i);
                        Map<String, String> pathParams = e.pathParams() == null ? Map.of() : e.pathParams();
                        statement.bind("id" + i, e.id())
                                .bind("event_time" + i, e.eventTime().toString())
                                .bind("workspace_id" + i, s(e.workspaceId()))
                                .bind("workspace_name" + i, s(e.workspaceName()))
                                .bind("actor" + i, s(e.actor()))
                                .bind("actor_type" + i, s(e.actorType()))
                                .bind("credential_id" + i, s(e.credentialId()))
                                .bind("action" + i, s(e.action()))
                                .bind("outcome" + i, s(e.outcome()))
                                .bind("http_method" + i, s(e.httpMethod()))
                                .bind("route" + i, s(e.route()))
                                .bind("path" + i, s(e.path()))
                                .bind("status" + i, e.status())
                                .bind("resource_type" + i, s(e.resourceType()))
                                .bind("resource_id" + i, s(e.resourceId()))
                                .bind("pp_keys" + i, pathParams.keySet().toArray(String[]::new))
                                .bind("pp_values" + i, pathParams.values().toArray(String[]::new))
                                .bind("required_permissions" + i, e.requiredPermissions() == null
                                        ? new String[0]
                                        : e.requiredPermissions().toArray(String[]::new))
                                .bind("client_ip" + i, s(e.clientIp()))
                                .bind("user_agent" + i, StringUtils.left(s(e.userAgent()), 512))
                                .bind("trace_id" + i, s(e.traceId()))
                                .bind("duration_ms" + i, Math.max(0, e.durationMs()))
                                .bind("details" + i, StringUtils.defaultIfBlank(e.details(), "{}"));
                    }
                    return statement.execute();
                })
                .then();
    }

    private static String s(String value) {
        return value == null ? "" : value;
    }
}
