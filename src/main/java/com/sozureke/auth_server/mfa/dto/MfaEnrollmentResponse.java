package com.sozureke.auth_server.mfa.dto;

public record MfaEnrollmentResponse(
    String otpauthUri, String manualEntryKey, String qrCodeDataUri) {}
