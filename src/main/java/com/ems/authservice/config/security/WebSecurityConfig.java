package com.ems.authservice.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {
  private final AuthenticationProvider authenticationProvider;
  private final UserInfoExtractionFilter userInfoExtractionFilter;
  private static final String[] WHITE_LIST_URL = {
          "/api/auth/login",
          "/api-docs"
  };

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .cors(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(req -> req
                    .requestMatchers(WHITE_LIST_URL).permitAll()
                    .anyRequest().authenticated()
            )
            .sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // No sessions, JWT only
            )
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(userInfoExtractionFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }
}
