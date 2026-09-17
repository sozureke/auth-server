package com.sozureke.auth_server.oauth;

import com.sozureke.auth_server.oauth.dto.OAuthClientResponse;
import com.sozureke.auth_server.oauth.dto.RegisterClientRequest;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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

  public OAuthClientController(
      RegisteredClientRepository registeredClientRepository, PasswordEncoder passwordEncoder) {
    this.registeredClientRepository = registeredClientRepository;
    this.passwordEncoder = passwordEncoder;
  }

  @PostMapping
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<OAuthClientResponse> register(
      @Valid @RequestBody RegisterClientRequest request) {
    String rawSecret = UUID.randomUUID().toString();

    RegisteredClient client =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(request.clientId())
            .clientSecret(passwordEncoder.encode(rawSecret))
            .clientName(request.clientName())
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUris(uris -> uris.addAll(request.redirectUris()))
            .scopes(scopes -> scopes.addAll(request.scopes()))
            .clientSettings(ClientSettings.builder().requireProofKey(true).build())
            .build();

    registeredClientRepository.save(client);

    return ResponseEntity.status(HttpStatus.CREATED)
        .body(new OAuthClientResponse(client.getClientId(), rawSecret));
  }
}
