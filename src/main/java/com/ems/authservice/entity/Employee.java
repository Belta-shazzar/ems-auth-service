package com.ems.authservice.entity;

import com.ems.authservice.entity.enums.Roles;
import com.ems.authservice.entity.enums.EmployeeStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Employee {

  private UUID id;

  private String email;

  private String password;

  private EmployeeStatus status;

  private Roles role;
}
