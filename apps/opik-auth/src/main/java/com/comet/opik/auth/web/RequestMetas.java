package com.comet.opik.auth.web;

import com.comet.opik.auth.domain.AccountService.RequestMeta;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;

public final class RequestMetas {

    private RequestMetas() {
    }

    public static RequestMeta of(HttpServletRequest request) {
        return RequestMeta.builder()
                .clientIp(clientIp(request))
                .userAgent(StringUtils.left(request.getHeader("User-Agent"), 512))
                .path(request.getRequestURI())
                .method(request.getMethod())
                .build();
    }

    /** First hop of X-Forwarded-For (set by nginx), else the socket peer. */
    public static String clientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (StringUtils.isNotBlank(xff)) {
            return StringUtils.left(xff.split(",")[0].strip(), 64);
        }
        String real = request.getHeader("X-Real-IP");
        if (StringUtils.isNotBlank(real)) {
            return StringUtils.left(real.strip(), 64);
        }
        return StringUtils.defaultString(request.getRemoteAddr());
    }
}
