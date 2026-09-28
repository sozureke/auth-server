package com.sozureke.auth_server.admin;

public class InvalidSortException extends RuntimeException {
  public InvalidSortException(String property) {
    super("Cannot sort by '" + property + "'");
  }
}
