package com.ems.authservice.exception;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ErrorMessage {
  private LocalDateTime timestamp;
  private int statusCode;
  private String message;
  private Map<String, String> validationErrors;
}
