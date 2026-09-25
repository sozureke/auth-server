package com.sozureke.auth_server.session;

public class SessionNotFoundException extends RuntimeException {

  public SessionNotFoundException() {
    super("Session not found");
  }
}
