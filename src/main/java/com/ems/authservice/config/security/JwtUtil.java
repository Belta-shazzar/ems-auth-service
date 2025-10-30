package com.ems.authservice.config.security;

import com.ems.authservice.entity.Employee;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

  @Value("${application.security.jwt.secret-key}")
  private String secret;

  @Value("${application.security.jwt.expiration}")
  public Long expiration;

  private SecretKey getSigningKey() {
//    TODO: Change signature to something valid
    return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
  }

  public String generateAccessToken(Employee employee) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("email", employee.getEmail());
    claims.put("role", "ROLE_" + employee.getRole());
    return generateToken(claims, employee.getId().toString(), expiration);
  }

  private String generateToken(
          Map<String, Object> claims,
          String subject,
          Long expirationTime
  ) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + expirationTime);

    return Jwts.builder()
        .claims(claims)
        .subject(subject)
        .issuedAt(now)
        .expiration(expiryDate)
        .signWith(getSigningKey())
        .compact();
  }
}
