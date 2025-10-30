package com.ems.authservice.config.security.user;

import com.ems.authservice.client.EmployeeClient;
import com.ems.authservice.entity.Employee;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AppUserService implements UserDetailsService {
   private final EmployeeClient employeeClient;

  public AppUserService(EmployeeClient employeeClient) {
    this.employeeClient = employeeClient;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    log.info("Attempting to load user by email: {}", username);
    try {
      Employee employee = employeeClient.getEmployeeByEmail(username);
      if (employee == null) {
        throw new UsernameNotFoundException("Employee with email " + username + " not found");
      }
      log.info("Successfully loaded employee: {}", username);
      return new AppUser(employee);
    } catch (Exception ex) {
      log.error("Error loading user by email {}: {}", username, ex.getMessage());
      throw new UsernameNotFoundException("User with email " + username + " not found");
    }
  }
}
