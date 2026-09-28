package com.sozureke.auth_server.admin;

public class AdminActionNotAllowedException extends RuntimeException {
  public AdminActionNotAllowedException(String message) {
    super(message);
  }
}
