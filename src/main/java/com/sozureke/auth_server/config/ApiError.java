package com.sozureke.auth_server.config;

import java.time.LocalDateTime;
import java.util.Map;

public class ApiError {

  private final int status;
  private final String message;
  private final LocalDateTime timestamp;
  private final Map<String, String> fieldErrors;

  public ApiError(int status, String message, Map<String, String> fieldErrors) {
    this.status = status;
    this.message = message;
    this.timestamp = LocalDateTime.now();
    this.fieldErrors = fieldErrors;
  }

  public int getStatus() {
    return status;
  }

  public String getMessage() {
    return message;
  }

  public LocalDateTime getTimestamp() {
    return timestamp;
  }

  public Map<String, String> getFieldErrors() {
    return fieldErrors;
  }
}
