
package com.connectly.auth.exception;

import java.time.Instant;

public record ApiError(
        String code,
        String message,
        Instant timestamp,
        String correlationId
) {
}
