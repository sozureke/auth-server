package com.sozureke.auth_server.mfa;

import com.sozureke.auth_server.auth.AuthUserDetails;
import com.sozureke.auth_server.mfa.dto.MfaCodeRequest;
import com.sozureke.auth_server.mfa.dto.MfaEnrollmentResponse;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth/mfa")
public class MfaController {
  private final MfaService mfaService;

  public MfaController(MfaService mfaService) {
    this.mfaService = mfaService;
  }

  @PostMapping("/enable")
  public ResponseEntity<MfaEnrollmentResponse> enable(
      @AuthenticationPrincipal AuthUserDetails principal) {
    return ResponseEntity.ok(mfaService.startEnrollment(principal.getUser()));
  }

  @GetMapping("/qr")
  public ResponseEntity<byte[]> qr(@AuthenticationPrincipal AuthUserDetails principal) {
    return ResponseEntity.ok()
        .contentType(MediaType.IMAGE_PNG)
        .body(mfaService.pendingEnrollmentQr(principal.getUser()));
  }

  @PostMapping("/verify-setup")
  public ResponseEntity<Void> verifySetup(
      @AuthenticationPrincipal AuthUserDetails principal,
      @Valid @RequestBody MfaCodeRequest request) {
    mfaService.confirmEnrollment(principal.getUser(), request.code());
    return ResponseEntity.ok().build();
  }
}
