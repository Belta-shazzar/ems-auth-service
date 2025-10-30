package com.ems.authservice.service;

import com.ems.authservice.config.security.user.AppUser;
import com.ems.authservice.dto.*;

public interface AuthService {

  AuthResponse login(LoginRequest request);

  void changePassword(ChangePasswordRequest request, AppUser user);
}
