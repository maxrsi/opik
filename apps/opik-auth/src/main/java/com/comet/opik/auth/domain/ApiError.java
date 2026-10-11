package com.comet.opik.auth.domain;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * Error with the JSON envelope opik-backend's RemoteAuthService understands ({@code ReactServiceErrorResponse}:
 * {@code {"msg": "...", "code": 401}}). Also used by the public /auth/api endpoints.
 */
public class ApiError extends WebApplicationException {

    public static final String NOT_LOGGED_IN = "Please login first";

    public ApiError(int status, String msg) {
        super(msg, Response.status(status)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(new Body(msg, status))
                .build());
    }

    public static ApiError unauthorized() {
        return new ApiError(401, NOT_LOGGED_IN);
    }

    public static ApiError unauthorized(String msg) {
        return new ApiError(401, msg);
    }

    public static ApiError forbidden(String msg) {
        return new ApiError(403, msg);
    }

    public static ApiError badRequest(String msg) {
        return new ApiError(400, msg);
    }

    public static ApiError notFound(String msg) {
        return new ApiError(404, msg);
    }

    public static ApiError conflict(String msg) {
        return new ApiError(409, msg);
    }

    public record Body(String msg, int code) {
    }
}
