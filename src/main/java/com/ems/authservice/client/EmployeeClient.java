package com.ems.authservice.client;

import com.ems.authservice.client.dto.EmployeeClientResponse;
import com.ems.authservice.entity.Employee;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "employee-service", fallback = EmployeeClientFallback.class)
public interface EmployeeClient {
  
  @GetMapping("/api/employees/email/{email}")
  @CircuitBreaker(name = "employeeService", fallbackMethod = "getEmployeeByEmailFallback")
  @Retry(name = "employeeService")
  Employee getEmployeeByEmail(@PathVariable String email);
}
