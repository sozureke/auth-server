package com.sozureke.auth_server.user;

public class EmailAlreadyExistsException extends RuntimeException {

    public EmailAlreadyExistsException(String email) {
        super("Email already in use: %s".formatted(email));
    }
}