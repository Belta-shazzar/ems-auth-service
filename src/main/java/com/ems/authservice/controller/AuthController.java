package com.ems.authservice.controller;

import com.ems.authservice.config.security.user.AppUser;
import com.ems.authservice.dto.*;
import com.ems.authservice.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "APIs for user authentication and password management")
public class AuthController {

  private final AuthService authService;

  @Operation(
          summary = "User login",
          description = "Authenticates a user with email and password, returns JWT tokens"
  )
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = "Login successful",
                  content = @Content(schema = @Schema(implementation = AuthResponse.class))),
          @ApiResponse(responseCode = "400", description = "Invalid input data"),
          @ApiResponse(responseCode = "401", description = "Invalid credentials")
  })
  @PostMapping("/login")
  public ResponseEntity<AuthResponse> login(
          @Parameter(description = "Login credentials", required = true)
          @Valid @RequestBody LoginRequest request) {
    AuthResponse response = authService.login(request);
    return ResponseEntity.ok(response);
  }

  @Operation(
          summary = "Change password",
          description = "Allows authenticated users to change their password",
          security = @SecurityRequirement(name = "Bearer Authentication")
  )
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = "Password changed successfully",
                  content = @Content(schema = @Schema(implementation = StringResponse.class))),
          @ApiResponse(responseCode = "400", description = "Invalid input data or password requirements not met"),
          @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT token")
  })
  @PostMapping("/change-password")
  public ResponseEntity<StringResponse> changePassword(
          @Parameter(description = "Password change request", required = true)
          @Valid @RequestBody ChangePasswordRequest request,
          @Parameter(hidden = true) @AuthenticationPrincipal AppUser user
  ) {
    authService.changePassword(request, user);
    return ResponseEntity.ok(new StringResponse("Password changed successfully"));
  }
}
