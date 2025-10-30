package com.ems.authservice.client.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmployeeClientResponse {
    private UUID id;
    private String email;
    private String password;
    private String role;
}
