package com.ems.authservice.client;

import com.ems.authservice.entity.Employee;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "employee-service")
public interface EmployeeClient {

    @GetMapping("/api/employees/email/{email}")
    Employee getEmployeeByEmail(@PathVariable String email);
}
