package com.sozureke.auth_server.admin;

public class ClientNotFoundException extends RuntimeException {
  public ClientNotFoundException() {
    super("Client not found");
  }
}
