package com.sozureke.auth_server.oauth;

import java.time.Duration;
import java.util.HashSet;
import java.util.stream.Collectors;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

@Service
public class CustomRegisteredClientRepository implements RegisteredClientRepository {
  private final OAuthClientRepository oAuthClientRepository;
  private static final TokenSettings TOKEN_SETTINGS =
      TokenSettings.builder()
          .accessTokenTimeToLive(Duration.ofMinutes(15))
          .refreshTokenTimeToLive(Duration.ofDays(7))
          .reuseRefreshTokens(false)
          .build();

  public CustomRegisteredClientRepository(OAuthClientRepository oAuthClientRepository) {
    this.oAuthClientRepository = oAuthClientRepository;
  }

  @Override
  public void save(RegisteredClient registeredClient) {
    OAuthClient entity =
        oAuthClientRepository.findById(registeredClient.getId()).orElseGet(OAuthClient::new);
    toEntity(registeredClient, entity);
    oAuthClientRepository.save(entity);
  }

  @Override
  public RegisteredClient findById(String id) {
    return oAuthClientRepository.findById(id).map(this::toRegisteredClient).orElse(null);
  }

  @Override
  public RegisteredClient findByClientId(String clientId) {
    return oAuthClientRepository
        .findByClientId(clientId)
        .map(this::toRegisteredClient)
        .orElse(null);
  }

  private RegisteredClient toRegisteredClient(OAuthClient entity) {
    return RegisteredClient.withId(entity.getId())
        .clientId(entity.getClientId())
        .clientSecret(entity.getClientSecret())
        .clientName(entity.getClientName())
        .clientAuthenticationMethods(
            methods ->
                entity
                    .getClientAuthenticationMethods()
                    .forEach(m -> methods.add(new ClientAuthenticationMethod(m))))
        .authorizationGrantTypes(
            grantTypes ->
                entity
                    .getAuthorizationGrantTypes()
                    .forEach(g -> grantTypes.add(new AuthorizationGrantType(g))))
        .redirectUris(uris -> uris.addAll(entity.getRedirectUris()))
        .scopes(scopes -> scopes.addAll(entity.getScopes()))
        .clientSettings(
            ClientSettings.builder()
                .requireProofKey(entity.isRequireProofKey())
                .requireAuthorizationConsent(false)
                .build())
        .tokenSettings(TOKEN_SETTINGS)
        .build();
  }

  private void toEntity(RegisteredClient registeredClient, OAuthClient entity) {
    entity.setId(registeredClient.getId());
    entity.setClientId(registeredClient.getClientId());
    entity.setClientSecret(registeredClient.getClientSecret());
    entity.setClientName(registeredClient.getClientName());
    entity.setClientAuthenticationMethods(
        registeredClient.getClientAuthenticationMethods().stream()
            .map(ClientAuthenticationMethod::getValue)
            .collect(Collectors.toSet()));
    entity.setAuthorizationGrantTypes(
        registeredClient.getAuthorizationGrantTypes().stream()
            .map(AuthorizationGrantType::getValue)
            .collect(Collectors.toSet()));
    entity.setRedirectUris(new HashSet<>(registeredClient.getRedirectUris()));
    entity.setScopes(new HashSet<>(registeredClient.getScopes()));
    entity.setRequireProofKey(registeredClient.getClientSettings().isRequireProofKey());
  }
}
