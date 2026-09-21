package com.sozureke.auth_server.config;

import com.sozureke.auth_server.auth.exception.AccountDisabledException;
import com.sozureke.auth_server.auth.exception.AccountLockedException;
import com.sozureke.auth_server.auth.exception.EmailNotVerifiedException;
import com.sozureke.auth_server.auth.exception.InvalidCredentialsException;
import com.sozureke.auth_server.auth.exception.InvalidResetTokenException;
import com.sozureke.auth_server.mfa.InvalidMfaCodeException;
import com.sozureke.auth_server.mfa.MfaAlreadyEnabledException;
import com.sozureke.auth_server.mfa.MfaNotStartedException;
import com.sozureke.auth_server.user.EmailAlreadyExistsException;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(EmailAlreadyExistsException.class)
  public ResponseEntity<ApiError> handleEmailExists(EmailAlreadyExistsException ex) {
    ApiError error = new ApiError(HttpStatus.CONFLICT.value(), ex.getMessage(), null);
    return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
  }

  @ExceptionHandler(MfaAlreadyEnabledException.class)
  public ResponseEntity<ApiError> handleMfaAlreadyEnabled(MfaAlreadyEnabledException ex) {
    ApiError error = new ApiError(HttpStatus.CONFLICT.value(), ex.getMessage(), null);
    return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
  }

  @ExceptionHandler(MfaNotStartedException.class)
  public ResponseEntity<ApiError> handleMfaNotStarted(MfaNotStartedException ex) {
    ApiError error = new ApiError(HttpStatus.CONFLICT.value(), ex.getMessage(), null);
    return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
  }

  @ExceptionHandler(InvalidMfaCodeException.class)
  public ResponseEntity<ApiError> handleInvalidMfaCode(InvalidMfaCodeException ex) {
    ApiError error = new ApiError(HttpStatus.BAD_REQUEST.value(), ex.getMessage(), null);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
  }

  @ExceptionHandler(InvalidCredentialsException.class)
  public ResponseEntity<ApiError> handleInvalidCredentials(InvalidCredentialsException ex) {
    ApiError error = new ApiError(HttpStatus.UNAUTHORIZED.value(), ex.getMessage(), null);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
  }

  @ExceptionHandler(AccountLockedException.class)
  public ResponseEntity<ApiError> handleAccountLocked(AccountLockedException ex) {
    ApiError error = new ApiError(HttpStatus.LOCKED.value(), ex.getMessage(), null);
    return ResponseEntity.status(HttpStatus.LOCKED).body(error);
  }

  @ExceptionHandler(EmailNotVerifiedException.class)
  public ResponseEntity<ApiError> handleEmailNotVerified(EmailNotVerifiedException ex) {
    ApiError error = new ApiError(HttpStatus.FORBIDDEN.value(), ex.getMessage(), null);
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
  }

  @ExceptionHandler(AccountDisabledException.class)
  public ResponseEntity<ApiError> handleAccountDisabled(AccountDisabledException ex) {
    ApiError error = new ApiError(HttpStatus.FORBIDDEN.value(), ex.getMessage(), null);
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
  }

  @ExceptionHandler(InvalidResetTokenException.class)
  public ResponseEntity<ApiError> handleInvalidResetToken(InvalidResetTokenException ex) {
    ApiError error = new ApiError(HttpStatus.BAD_REQUEST.value(), ex.getMessage(), null);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
  }

  @ExceptionHandler(InvalidVerificationTokenException.class)
  public ResponseEntity<ApiError> handleInvalidVerificationToken(
      InvalidVerificationTokenException ex) {
    ApiError error = new ApiError(HttpStatus.NOT_FOUND.value(), ex.getMessage(), null);
    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiError> handleValidationErrors(MethodArgumentNotValidException ex) {
    Map<String, String> fieldErrors = new HashMap<>();

    for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
      fieldErrors.put(fieldError.getField(), fieldError.getDefaultMessage());
    }

    ApiError error = new ApiError(HttpStatus.BAD_REQUEST.value(), "Validation failed", fieldErrors);

    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
  }
}
