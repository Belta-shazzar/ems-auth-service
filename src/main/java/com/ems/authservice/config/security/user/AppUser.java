package com.ems.authservice.config.security.user;

import com.ems.authservice.entity.Employee;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;


public record AppUser(Employee user) implements UserDetails {

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return this.user.getRole().getGrantedAuthorities();
  }

  @Override
  public String getPassword() {
    return user.getPassword();
  }

  @Override
  public String getUsername() {
    return user.getEmail();
  }

}
