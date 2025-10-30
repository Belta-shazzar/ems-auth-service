package com.ems.authservice.exception.custom;

public class AuthenticationException extends RuntimeException {
  public AuthenticationException(String message) {
    super(message);
  }
}
