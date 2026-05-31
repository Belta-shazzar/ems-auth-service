package com.ems.authservice.client;

import com.ems.authservice.entity.Employee;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

// dev: the url is empty → Feign uses lb://employee-service (Eureka)
// prod: url resolved from Parameter Store /config/auth-service/services.employee.url
@FeignClient(name = "employee-service", url = "${services.employee.url:}")
public interface EmployeeClient {

    @GetMapping("/api/employees/email/{email}")
    Employee getEmployeeByEmail(@PathVariable String email);
}
