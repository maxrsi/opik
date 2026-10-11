package com.comet.opik.infrastructure.auth;

import com.comet.opik.infrastructure.AuthenticationConfig;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.container.ResourceInfo;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.StringUtils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Optional "deny by default" for write endpoints without {@link RequiredPermissions}.
 * <p>
 * When {@code authentication.unannotatedWritePermission} is configured, every POST/PUT/PATCH/DELETE resource method
 * that declares no permission (and is not listed in {@code authentication.unannotatedWriteExemptions}) requires that
 * permission instead of none. Turning the gap into a concrete required permission makes the remote auth service
 * decide, and keeps the API-key cache keyed per permission (a key with no required permission would be served from
 * the permission-less cache entry).
 * <p>
 * Not configured (default): returns the declared permissions unchanged, i.e. upstream behaviour.
 */
@UtilityClass
public class UnannotatedWritePermissionPolicy {

    private static final Set<String> WRITE_METHODS = Set.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH,
            HttpMethod.DELETE);

    public List<String> apply(List<String> declared, ResourceInfo resourceInfo, AuthenticationConfig config) {
        if (config == null || StringUtils.isBlank(config.getUnannotatedWritePermission())
                || (declared != null && !declared.isEmpty())
                || resourceInfo == null || resourceInfo.getResourceMethod() == null) {
            return declared;
        }
        Method method = resourceInfo.getResourceMethod();
        Class<?> resourceClass = Optional.<Class<?>>ofNullable(resourceInfo.getResourceClass())
                .orElse(method.getDeclaringClass());
        if (!isWrite(method) || parseExemptions(config.getUnannotatedWriteExemptions())
                .contains(key(resourceClass, method))) {
            return declared;
        }
        return List.of(config.getUnannotatedWritePermission().strip());
    }

    public boolean isWrite(Method method) {
        return httpMethod(method).map(WRITE_METHODS::contains).orElse(false);
    }

    public Optional<String> httpMethod(Method method) {
        for (Annotation annotation : method.getAnnotations()) {
            HttpMethod httpMethod = annotation.annotationType().getAnnotation(HttpMethod.class);
            if (httpMethod != null) {
                return Optional.of(httpMethod.value());
            }
        }
        return Optional.empty();
    }

    public String key(Class<?> resourceClass, Method method) {
        return resourceClass.getSimpleName() + "#" + method.getName();
    }

    public Set<String> parseExemptions(String exemptions) {
        if (StringUtils.isBlank(exemptions)) {
            return Set.of();
        }
        return Arrays.stream(exemptions.split(","))
                .map(String::strip)
                .filter(StringUtils::isNotBlank)
                .collect(Collectors.toUnmodifiableSet());
    }
}
