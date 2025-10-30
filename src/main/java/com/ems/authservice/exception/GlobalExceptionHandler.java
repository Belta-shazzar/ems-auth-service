package com.ems.authservice.exception;

import com.ems.authservice.exception.custom.AuthenticationException;
import com.ems.authservice.exception.custom.ResourceNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(AuthenticationException.class)
  public ResponseEntity<ErrorMessage> handleAuthenticationException(AuthenticationException ex) {
    ErrorMessage error = ErrorMessage.builder()
        .timestamp(LocalDateTime.now())
        .statusCode(HttpStatus.UNAUTHORIZED.value())
        .message(ex.getMessage())
        .build();
    return new ResponseEntity<>(error, HttpStatus.UNAUTHORIZED);
  }

  @ExceptionHandler(ResourceNotFoundException.class)
  public ResponseEntity<ErrorMessage> handleResourceNotFoundException(ResourceNotFoundException ex) {
    ErrorMessage error = ErrorMessage.builder()
        .timestamp(LocalDateTime.now())
        .statusCode(HttpStatus.NOT_FOUND.value())
        .message(ex.getMessage())
        .build();
    return new ResponseEntity<>(error, HttpStatus.NOT_FOUND);
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ErrorMessage> handleValidationExceptions(MethodArgumentNotValidException ex) {
    Map<String, String> errors = new HashMap<>();
    ex.getBindingResult().getAllErrors().forEach((error) -> {
      String fieldName = ((FieldError) error).getField();
      String errorMessage = error.getDefaultMessage();
      errors.put(fieldName, errorMessage);
    });
    
    ErrorMessage error = ErrorMessage.builder()
        .timestamp(LocalDateTime.now())
        .statusCode(HttpStatus.BAD_REQUEST.value())
        .message("Invalid input")
        .validationErrors(errors)
        .build();
    return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorMessage> handleGlobalException(Exception ex) {
    ErrorMessage error = ErrorMessage.builder()
        .timestamp(LocalDateTime.now())
        .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
        .message(ex.getMessage())
        .build();
    return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
  }
}
