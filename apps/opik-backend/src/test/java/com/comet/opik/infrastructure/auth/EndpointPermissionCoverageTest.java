package com.comet.opik.infrastructure.auth;

import com.comet.opik.api.resources.v1.priv.TracesResource;
import jakarta.ws.rs.Path;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fork guard: every write resource method must be classified. Lists all POST/PUT/PATCH/DELETE methods without
 * {@link RequiredPermissions} and compares them with {@code src/test/resources/fork/unannotated-writes.txt}.
 * A new un-annotated write endpoint (e.g. after syncing upstream) fails this test until someone decides whether it
 * is a read-only POST (annotate with a *_VIEW permission), an exemption, or a real write covered by the
 * {@code authentication.unannotatedWritePermission} fallback.
 */
class EndpointPermissionCoverageTest {

    private static final String RESOURCES_PACKAGE = "com/comet/opik/api/resources";

    @Test
    void unannotatedWriteEndpointsAreClassified() throws Exception {
        var actual = scanUnannotatedWrites();
        var expected = readExpected();

        var added = new TreeSet<>(actual);
        added.removeAll(expected);
        var removed = new TreeSet<>(expected);
        removed.removeAll(actual);

        assertThat(added)
                .as("New write endpoints without @RequiredPermissions: classify them (see unannotated-writes.txt)")
                .isEmpty();
        assertThat(removed)
                .as("Entries in unannotated-writes.txt that no longer exist or are now annotated: remove them")
                .isEmpty();
    }

    @Test
    void readOnlyPostsCarryViewPermissions() throws Exception {
        // These POST endpoints only read data; without a VIEW annotation the write fallback would lock out Viewers.
        var mustBeAnnotated = new String[]{
                "TracesResource#searchTraces", "TracesResource#searchTraceThreads", "TracesResource#getTraceThread",
                "SpansResource#searchSpans", "WorkspacesResource#metricsSummary", "WorkspacesResource#getMetric",
                "WorkspacesResource#costsSummary", "WorkspacesResource#getCost",
                "DatasetsResource#getDatasetByIdentifier", "DatasetsResource#streamDatasetItems",
                "DatasetsResource#startDatasetExport", "ExperimentsResource#streamExperiments",
                "ExperimentsResource#streamExperimentItems"};
        assertThat(scanUnannotatedWrites()).doesNotContain(mustBeAnnotated);
    }

    static TreeSet<String> scanUnannotatedWrites() throws IOException, URISyntaxException, ClassNotFoundException {
        var classesRoot = Paths.get(TracesResource.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        var result = new TreeSet<String>();
        try (var files = Files.walk(classesRoot.resolve(RESOURCES_PACKAGE))) {
            for (var file : files.filter(f -> f.toString().endsWith(".class") && !f.toString().contains("$"))
                    .toList()) {
                String className = classesRoot.relativize(file).toString()
                        .replace(file.getFileSystem().getSeparator(), ".").replaceAll("\\.class$", "");
                Class<?> resource = Class.forName(className, false, EndpointPermissionCoverageTest.class
                        .getClassLoader());
                if (!resource.isAnnotationPresent(Path.class)) {
                    continue;
                }
                for (Method method : resource.getDeclaredMethods()) {
                    if (Modifier.isPublic(method.getModifiers())
                            && UnannotatedWritePermissionPolicy.isWrite(method)
                            && !method.isAnnotationPresent(RequiredPermissions.class)) {
                        result.add(UnannotatedWritePermissionPolicy.key(resource, method));
                    }
                }
            }
        }
        return result;
    }

    static TreeSet<String> readExpected() throws IOException {
        try (var in = Objects.requireNonNull(EndpointPermissionCoverageTest.class.getResourceAsStream(
                "/fork/unannotated-writes.txt"))) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).lines()
                    .map(String::strip)
                    .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                    .collect(Collectors.toCollection(TreeSet::new));
        }
    }
}
