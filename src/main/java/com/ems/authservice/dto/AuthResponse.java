package com.ems.authservice.dto;

import java.util.UUID;

public record AuthResponse(
        UUID employeeId,
        String email,
        String accessToken,
        Long expiresIn
) {
}