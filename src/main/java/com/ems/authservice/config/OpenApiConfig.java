package com.ems.authservice.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

  @Bean
  public OpenAPI authServiceOpenAPI() {
    return new OpenAPI()
            .info(new Info()
                    .title("Employee Management Service API: Authentication Service API")
                    .description("REST API for authentication and authorization in the Employee Management System")
                    .version("1.0.0")
                    .contact(new Contact()
                            .name("EMS Team")
                            .email("support@ems.com"))
            )
            .servers(List.of(
                    new Server().url("http://localhost:8010").description("Local Development Server"),
                    new Server().url("http://localhost:8000/auth-service").description("API Gateway")
            ))
            .addSecurityItem(new SecurityRequirement().addList("Bearer Authentication"))
            .components(new io.swagger.v3.oas.models.Components()
                    .addSecuritySchemes("Bearer Authentication",
                            new SecurityScheme()
                                    .type(SecurityScheme.Type.HTTP)
                                    .scheme("bearer")
                                    .bearerFormat("JWT")
                                    .description("Enter JWT token")));
  }
}
