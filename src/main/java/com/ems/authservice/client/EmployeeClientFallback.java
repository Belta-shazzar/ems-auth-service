package com.ems.authservice.client;

import com.ems.authservice.entity.Employee;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class EmployeeClientFallback implements EmployeeClient {

    @Override
    public Employee getEmployeeByEmail(String email) {
        log.error("Employee service is unavailable. Fallback triggered for email: {}", email);
        throw new RuntimeException("Employee service is currently unavailable. Please try again later.");
    }
}
