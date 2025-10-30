package com.ems.authservice.entity.enums;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;

@Getter
public enum Roles {

  ADMIN,
  MANAGER,
  EMPLOYEE;

  public Set<? extends GrantedAuthority> getGrantedAuthorities() {
    return Set.of(new SimpleGrantedAuthority("ROLE_" + this.name()));
  }
}