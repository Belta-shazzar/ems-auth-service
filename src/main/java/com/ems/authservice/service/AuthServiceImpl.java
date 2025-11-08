package com.ems.authservice.service;

import com.ems.authservice.client.EmployeeClient;
import com.ems.authservice.config.security.user.AppUser;
import com.ems.authservice.dto.*;
import com.ems.authservice.entity.Employee;
import com.ems.authservice.entity.enums.EmployeeStatus;
import com.ems.authservice.exception.custom.AuthenticationException;
import com.ems.authservice.config.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {


  private final EmployeeClient employeeClient;
  private final PasswordEncoder passwordEncoder;
  private final JwtUtil jwtUtil;

  @Override
  public AuthResponse login(LoginRequest request) {
    log.info("Login attempt for email: {}", request.email());

    // Fetch employee data from employee service
    Employee employee;
    try {
      employee = employeeClient.getEmployeeByEmail(request.email());

//      TODO: Properly handle not found emails
    } catch (Exception e) {
      log.error("Failed to fetch employee data: {}", e.getMessage());
      throw new AuthenticationException("Unable to fetch employee data");
    }

    if (employee == null || !passwordEncoder.matches(request.password(), employee.getPassword())) {
      throw new AuthenticationException("Invalid email or password");
    }

    if (!employee.getStatus().equals(EmployeeStatus.ACTIVE)) {
      throw new AuthenticationException("Account is not active");
    }

    String accessToken = jwtUtil.generateAccessToken(employee);

    log.info("Login successful for email: {}", request.email());

    return new AuthResponse(
            employee.getId(),
            employee.getEmail(),
            accessToken,
            jwtUtil.expiration
    );
  }

  @Override
  public void changePassword(ChangePasswordRequest request, AppUser user) {
    String username = user.getUsername();
    log.info("Changing password for email: {}", username);

    if (!passwordEncoder.matches(request.currentPassword(), user.getPassword())) {
      throw new AuthenticationException("Current password is incorrect");
    }
//
//    // Hash and save new password
    String newPassword = passwordEncoder.encode(request.newPassword());

    Employee employee = Employee.builder()
            .email(username)
            .password(newPassword)
            .build();

//    TODO: Publish event to update employee's password
    log.info("Password changed successfully for email: {}", username);
  }
}
