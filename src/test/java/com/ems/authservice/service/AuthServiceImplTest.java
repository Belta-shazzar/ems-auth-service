package com.ems.authservice.service;

import com.ems.authservice.client.EmployeeClient;
import com.ems.authservice.config.security.JwtUtil;
import com.ems.authservice.config.security.user.AppUser;
import com.ems.authservice.dto.AuthResponse;
import com.ems.authservice.dto.ChangePasswordRequest;
import com.ems.authservice.dto.LoginRequest;
import com.ems.authservice.entity.Employee;
import com.ems.authservice.entity.enums.EmployeeStatus;
import com.ems.authservice.exception.custom.AuthenticationException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import java.util.UUID;


@Slf4j
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthServiceImpl Unit Tests")
class AuthServiceImplTest {
  @Mock
  private EmployeeClient employeeClient;
  @Mock
  private PasswordEncoder passwordEncoder;
  @Mock
  private JwtUtil jwtUtil;

  @InjectMocks
  private AuthServiceImpl authService;

  private Employee testEmployee;
  private LoginRequest testLoginRequest;
  private static final String TEST_EMAIL = "test@example.com";
  private static final String TEST_PASSWORD = "password123";
  private static final String ENCODED_PASSWORD = "$2a$10$encodedPassword";
  private static final String ACCESS_TOKEN = "jwt.access.token";
  private static final Long TOKEN_EXPIRATION = 3600000L;

  @BeforeEach
  void setUp() {
    testEmployee = Employee.builder().id(UUID.randomUUID()).email(TEST_EMAIL).password(ENCODED_PASSWORD).status(EmployeeStatus.ACTIVE).build();

    testLoginRequest = new LoginRequest(TEST_EMAIL, TEST_PASSWORD);

    jwtUtil.expiration = TOKEN_EXPIRATION;
  }

  @Nested
  @DisplayName("Login Tests")
  class LoginTests {

    @Test
    @DisplayName(("Successfully login with valid credentials"))
    void shouldLoginSuccessfully() {
      // Given
      when(employeeClient.getEmployeeByEmail(TEST_EMAIL)).thenReturn(testEmployee);
      when(passwordEncoder.matches(TEST_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);
      when(jwtUtil.generateAccessToken(testEmployee)).thenReturn(ACCESS_TOKEN);

      // When
      AuthResponse response = authService.login(testLoginRequest);

      // Then
      assertThat(response).isNotNull();
      assertThat(response.employeeId()).isEqualTo(testEmployee.getId());
      assertThat(response.email()).isEqualTo(TEST_EMAIL);
      assertThat(response.accessToken()).isEqualTo(ACCESS_TOKEN);
      assertThat(response.expiresIn()).isEqualTo(TOKEN_EXPIRATION);

      verify(employeeClient).getEmployeeByEmail(TEST_EMAIL);
      verify(passwordEncoder).matches(TEST_PASSWORD, ENCODED_PASSWORD);
      verify(jwtUtil).generateAccessToken(testEmployee);
    }

    @Test
    @DisplayName("Should throw exception when employee service fails")
    void shouldThrowExceptionWhenEmployeeServiceFails() {
      // Given
      when(employeeClient.getEmployeeByEmail(TEST_EMAIL)).thenThrow(new RuntimeException("Service unavailable"));

      // When & Then
      assertThatThrownBy(() -> authService.login(testLoginRequest)).isInstanceOf(AuthenticationException.class).hasMessage("Unable to fetch employee data");

      verify(employeeClient).getEmployeeByEmail(TEST_EMAIL);
      verify(passwordEncoder, never()).matches(anyString(), anyString());
      verify(jwtUtil, never()).generateAccessToken(any());
    }

//    @Test
//    @DisplayName("Should throw exception when employee not found (null)")
//    void shouldThrowExceptionWhenEmployeeNotFound() {
//      // Given
//      when(employeeClient.getEmployeeByEmail(TEST_EMAIL)).thenReturn(null);
//
//      // When & Then
//      assertThatThrownBy(() -> authService.login(loginRequest))
//              .isInstanceOf(AuthenticationException.class)
//              .hasMessage("Invalid email or password");
//
//      verify(employeeClient).getEmployeeByEmail(TEST_EMAIL);
//      verify(passwordEncoder, never()).matches(anyString(), anyString());
//      verify(jwtUtil, never()).generateAccessToken(any());
//    }

    @Test
    @DisplayName("Should throw exception when password does not match")
    void shouldThrowExceptionWhenPasswordDoesNotMatch() {
      // Given
      when(employeeClient.getEmployeeByEmail(TEST_EMAIL)).thenReturn(testEmployee);
      when(passwordEncoder.matches(TEST_PASSWORD, ENCODED_PASSWORD)).thenReturn(false);

      // When & Then
      assertThatThrownBy(() -> authService.login(testLoginRequest))
              .isInstanceOf(AuthenticationException.class)
              .hasMessage("Invalid email or password");

      verify(employeeClient).getEmployeeByEmail(TEST_EMAIL);
      verify(passwordEncoder).matches(TEST_PASSWORD, ENCODED_PASSWORD);
      verify(jwtUtil, never()).generateAccessToken(any());
    }

    @Test
    @DisplayName("Should throw exception when employee status is INACTIVE")
    void shouldThrowExceptionWhenEmployeeIsInactive() {
      // Given
      testEmployee.setStatus(EmployeeStatus.PENDING);
      when(employeeClient.getEmployeeByEmail(TEST_EMAIL)).thenReturn(testEmployee);
      when(passwordEncoder.matches(TEST_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);

      // When & Then
      assertThatThrownBy(() -> authService.login(testLoginRequest))
              .isInstanceOf(AuthenticationException.class)
              .hasMessage("Account is not active");

      verify(employeeClient).getEmployeeByEmail(TEST_EMAIL);
      verify(passwordEncoder).matches(TEST_PASSWORD, ENCODED_PASSWORD);
      verify(jwtUtil, never()).generateAccessToken(any());
    }
  }

  @Nested
  @DisplayName("Change Password Tests")
  class ChangePasswordTests {

    private AppUser appUser;
    private ChangePasswordRequest changePasswordRequest;
    private static final String CURRENT_PASSWORD = "currentPassword";
    private static final String NEW_PASSWORD = "newPassword123";
    private static final String ENCODED_NEW_PASSWORD = "$2a$10$encodedNewPassword";

    @BeforeEach
    void setUp() {
      appUser = mock(AppUser.class);
      when(appUser.getUsername()).thenReturn(TEST_EMAIL);
      when(appUser.getPassword()).thenReturn(ENCODED_PASSWORD);

      changePasswordRequest = new ChangePasswordRequest(CURRENT_PASSWORD, NEW_PASSWORD);
    }

    @Test
    @DisplayName("Should successfully change password with valid current password")
    void shouldChangePasswordSuccessfully() {
      // Given
      when(passwordEncoder.matches(CURRENT_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);
      log.info("First junction");
      when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(ENCODED_NEW_PASSWORD);
      log.info("Second junction");

      // When
      authService.changePassword(changePasswordRequest, appUser);
      log.info("Third junction");

      // Then
      verify(appUser).getUsername();
      verify(appUser).getPassword();
      verify(passwordEncoder).matches(CURRENT_PASSWORD, ENCODED_PASSWORD);
      verify(passwordEncoder).encode(NEW_PASSWORD);
    }

    @Test
    @DisplayName("Should throw exception when current password is incorrect")
    void shouldThrowExceptionWhenCurrentPasswordIsIncorrect() {
      // Given
      when(passwordEncoder.matches(CURRENT_PASSWORD, ENCODED_PASSWORD)).thenReturn(false);

      // When & Then
      assertThatThrownBy(() -> authService.changePassword(changePasswordRequest, appUser))
              .isInstanceOf(AuthenticationException.class)
              .hasMessage("Current password is incorrect");

      verify(appUser).getPassword();
      verify(passwordEncoder).matches(CURRENT_PASSWORD, ENCODED_PASSWORD);
      verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    @DisplayName("Should handle password change for different users")
    void shouldHandlePasswordChangeForDifferentUsers() {
      // Given
      String anotherEmail = "another@example.com";
      when(appUser.getUsername()).thenReturn(anotherEmail);
      when(passwordEncoder.matches(CURRENT_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);
      when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(ENCODED_NEW_PASSWORD);

      // When
      authService.changePassword(changePasswordRequest, appUser);

      // Then
      verify(appUser, atLeastOnce()).getUsername();
      verify(passwordEncoder).matches(CURRENT_PASSWORD, ENCODED_PASSWORD);
      verify(passwordEncoder).encode(NEW_PASSWORD);
    }
  }

}