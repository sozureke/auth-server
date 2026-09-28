package com.sozureke.auth_server.audit;

public enum AuditEventType {
  LOGIN,
  LOGIN_FAILED,
  LOGOUT,
  REGISTER,
  PASSWORD_CHANGE,
  MFA_ENABLE,
  MFA_DISABLE,
  TOKEN_ISSUED,
  TOKEN_REVOKED,
  USER_DISABLED,
  CLIENT_CREATED
}
