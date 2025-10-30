package com.ems.authservice;

import com.ems.authservice.client.EmployeeClient;
import com.ems.authservice.config.security.JwtUtil;
import com.ems.authservice.dto.LoginRequest;
import com.ems.authservice.dto.AuthResponse;
import com.ems.authservice.entity.Employee;
import com.ems.authservice.entity.enums.Roles;
import com.ems.authservice.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Auth Service Unit Tests")
class AuthServiceTest {

    @Mock
    private EmployeeClient employeeClient;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthService authService;

    private Employee testEmployee;
    private LoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        testEmployee = Employee.builder()
                .id(UUID.randomUUID())
                .email("john.doe@example.com")
                .password(passwordEncoder.encode("password123"))
                .role(Roles.EMPLOYEE)
                .build();

        loginRequest = new LoginRequest("john.doe@example.com", "password123");
    }

    @Test
    @DisplayName("Should login successfully with valid credentials")
    void shouldLoginSuccessfullyWithValidCredentials() {
        // Given
        when(employeeClient.getEmployeeByEmail(loginRequest.email()))
                .thenReturn(testEmployee);
        when(passwordEncoder.matches(loginRequest.password(), testEmployee.getPassword()))
                .thenReturn(true);
        when(jwtUtil.generateAccessToken(testEmployee))
                .thenReturn("access-token");

        // When
        AuthResponse response = authService.login(loginRequest);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.accessToken()).isEqualTo("access-token");
        
        verify(employeeClient).getEmployeeByEmail(loginRequest.email());
        verify(passwordEncoder).matches(loginRequest.password(), testEmployee.getPassword());
        verify(jwtUtil).generateAccessToken(testEmployee);
    }

    @Test
    @DisplayName("Should throw exception when employee not found")
    void shouldThrowExceptionWhenEmployeeNotFound() {
        // Given
        when(employeeClient.getEmployeeByEmail(loginRequest.email()))
                .thenThrow(new RuntimeException("Employee not found"));

        // When & Then
        assertThatThrownBy(() -> authService.login(loginRequest))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Employee not found");

        verify(employeeClient).getEmployeeByEmail(loginRequest.email());
        verify(passwordEncoder, never()).matches(anyString(), anyString());
        verify(jwtUtil, never()).generateAccessToken(testEmployee);
    }

    @Test
    @DisplayName("Should throw exception when password is invalid")
    void shouldThrowExceptionWhenPasswordIsInvalid() {
        // Given
        when(employeeClient.getEmployeeByEmail(loginRequest.email()))
                .thenReturn(testEmployee);
        when(passwordEncoder.matches(loginRequest.password(), testEmployee.getPassword()))
                .thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> authService.login(loginRequest))
                .isInstanceOf(BadCredentialsException.class);

        verify(employeeClient).getEmployeeByEmail(loginRequest.email());
        verify(passwordEncoder).matches(loginRequest.password(), testEmployee.getPassword());
        verify(jwtUtil, never()).generateAccessToken(testEmployee);
    }
}
