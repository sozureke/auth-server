package com.sozureke.auth_server.oauth;

import com.sozureke.auth_server.audit.AuditEventType;
import com.sozureke.auth_server.audit.AuditService;
import com.sozureke.auth_server.auth.AuthUserDetails;
import com.sozureke.auth_server.oauth.dto.OAuthClientResponse;
import com.sozureke.auth_server.oauth.dto.RegisterClientRequest;
import jakarta.validation.Valid;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/clients")
public class OAuthClientController {
  private final RegisteredClientRepository registeredClientRepository;
  private final PasswordEncoder passwordEncoder;
  private final AuditService auditService;

  public OAuthClientController(
      RegisteredClientRepository registeredClientRepository,
      PasswordEncoder passwordEncoder,
      AuditService auditService) {
    this.registeredClientRepository = registeredClientRepository;
    this.passwordEncoder = passwordEncoder;
    this.auditService = auditService;
  }

  @PostMapping
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<OAuthClientResponse> register(
      @AuthenticationPrincipal AuthUserDetails principal,
      @Valid @RequestBody RegisterClientRequest request) {
    String rawSecret = UUID.randomUUID().toString();
    String hashedSecret = passwordEncoder.encode(rawSecret);

    RegisteredClient client =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(request.clientId())
            .clientSecret(hashedSecret)
            .clientName(request.clientName())
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUris(uris -> uris.addAll(request.redirectUris()))
            .scopes(scopes -> scopes.addAll(request.scopes()))
            .clientSettings(ClientSettings.builder().requireProofKey(true).build())
            .build();

    registeredClientRepository.save(client);

    auditService.log(
        principal.getUser().getId(),
        AuditEventType.CLIENT_CREATED,
        "client",
        client.getClientId(),
        Map.of("clientName", request.clientName(), "scopes", request.scopes()));

    return ResponseEntity.status(HttpStatus.CREATED)
        .body(new OAuthClientResponse(client.getClientId(), rawSecret));
  }
}
