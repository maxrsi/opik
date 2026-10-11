package com.comet.opik.auth.audit;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class AuditQueryServiceTest {

    @Test
    void userInputOnlyTravelsAsQueryParameters() {
        var criteria = AuditQueryService.Criteria.builder()
                .workspaceId("ws").from(Instant.ofEpochMilli(1)).to(Instant.ofEpochMilli(2))
                .actor("alice' OR 1=1 --").action("projects.").outcome("denied").status(403).build();
        var q = AuditQueryService.buildWhere(criteria);
        assertThat(q.where()).doesNotContain("alice").doesNotContain("projects.")
                .contains("actor = {actor:String}").contains("startsWith(action, {action:String})")
                .contains("status = {status:UInt16}");
        assertThat(q.params()).containsEntry("actor", "alice' OR 1=1 --").containsEntry("ws", "ws")
                .containsEntry("from", "1").containsEntry("to", "2");
    }
}
