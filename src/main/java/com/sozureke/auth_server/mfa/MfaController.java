package com.sozureke.auth_server.mfa;

import com.sozureke.auth_server.auth.AuthUserDetails;
import com.sozureke.auth_server.mfa.dto.BackupCodesResponse;
import com.sozureke.auth_server.mfa.dto.MfaCodeRequest;
import com.sozureke.auth_server.mfa.dto.MfaDisableRequest;
import com.sozureke.auth_server.mfa.dto.MfaEnrollmentResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "MFA", description = "TOTP enrollment and backup codes")
public class MfaController {
  private final MfaService mfaService;

  public MfaController(MfaService mfaService) {
    this.mfaService = mfaService;
  }

  @PostMapping("/enable")
  @Operation(
      summary = "Start TOTP enrollment",
      description =
          "Generates a pending secret and returns it with an otpauth:// URI. MFA stays off until"
              + " the first code is confirmed with verify-setup.")
  @ApiResponse(responseCode = "200", description = "Enrollment started")
  @ApiResponse(responseCode = "409", description = "MFA already enabled")
  public ResponseEntity<MfaEnrollmentResponse> enable(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal) {
    return ResponseEntity.ok(mfaService.startEnrollment(principal.getUser()));
  }

  @GetMapping("/qr")
  @Operation(summary = "QR code of the pending enrollment")
  @ApiResponse(
      responseCode = "200",
      description = "PNG image",
      content = @Content(mediaType = MediaType.IMAGE_PNG_VALUE))
  @ApiResponse(responseCode = "409", description = "No enrollment in progress")
  public ResponseEntity<byte[]> qr(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal) {
    return ResponseEntity.ok()
        .contentType(MediaType.IMAGE_PNG)
        .body(mfaService.pendingEnrollmentQr(principal.getUser()));
  }

  @PostMapping("/verify-setup")
  @Operation(
      summary = "Confirm enrollment with the first TOTP code",
      description =
          "Turns MFA on and returns 10 single-use backup codes. They are shown only once.")
  @ApiResponse(responseCode = "200", description = "MFA enabled, backup codes returned")
  @ApiResponse(responseCode = "400", description = "Wrong code")
  @ApiResponse(responseCode = "409", description = "No enrollment in progress")
  public ResponseEntity<BackupCodesResponse> verifySetup(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal,
      @Valid @RequestBody MfaCodeRequest request) {
    return ResponseEntity.ok(mfaService.confirmEnrollment(principal.getUser(), request.code()));
  }

  @PostMapping("/disable")
  @Operation(
      summary = "Disable MFA",
      description = "Requires the account password. Deletes the secret and all backup codes.")
  @ApiResponse(responseCode = "200", description = "MFA disabled")
  @ApiResponse(responseCode = "401", description = "Wrong password")
  @ApiResponse(responseCode = "409", description = "MFA was not enabled")
  public ResponseEntity<Void> disable(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal,
      @Valid @RequestBody MfaDisableRequest request) {
    mfaService.disable(principal.getUser(), request.password());
    return ResponseEntity.ok().build();
  }
}
