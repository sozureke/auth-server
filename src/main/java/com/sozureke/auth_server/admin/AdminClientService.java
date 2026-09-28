package com.sozureke.auth_server.admin;

import com.sozureke.auth_server.admin.dto.UpdateClientRequest;
import com.sozureke.auth_server.audit.AuditEventType;
import com.sozureke.auth_server.audit.AuditService;
import com.sozureke.auth_server.oauth.OAuthClient;
import com.sozureke.auth_server.oauth.OAuthClientRepository;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AdminClientService {

  public static final Set<String> SORTABLE = Set.of("clientId", "clientName", "createdAt");

  private final OAuthClientRepository clientRepository;
  private final PasswordEncoder passwordEncoder;
  private final AuditService auditService;

  public AdminClientService(
      OAuthClientRepository clientRepository,
      PasswordEncoder passwordEncoder,
      AuditService auditService) {
    this.clientRepository = clientRepository;
    this.passwordEncoder = passwordEncoder;
    this.auditService = auditService;
  }

  @Transactional(readOnly = true)
  public Page<OAuthClient> list(Pageable pageable) {
    SortWhitelist.check(pageable, SORTABLE);
    return clientRepository.findAll(pageable);
  }

  @Transactional(readOnly = true)
  public OAuthClient get(String clientId) {
    return clientRepository.findByClientId(clientId).orElseThrow(ClientNotFoundException::new);
  }

  @Transactional
  public OAuthClient update(Long actorId, String clientId, UpdateClientRequest request) {
    OAuthClient client = get(clientId);
    client.setClientName(request.clientName());
    client.setRedirectUris(new HashSet<>(request.redirectUris()));
    client.setScopes(new HashSet<>(request.scopes()));
    clientRepository.save(client);
    auditService.log(
        actorId,
        AuditEventType.CLIENT_UPDATED,
        "client",
        clientId,
        Map.of("clientName", request.clientName(), "scopes", request.scopes()));
    return client;
  }

  @Transactional
  public void delete(Long actorId, String clientId) {
    clientRepository.delete(get(clientId));
    auditService.log(actorId, AuditEventType.CLIENT_DELETED, "client", clientId, Map.of());
  }

  @Transactional
  public String rotateSecret(Long actorId, String clientId) {
    OAuthClient client = get(clientId);
    String rawSecret = UUID.randomUUID().toString();
    client.setClientSecret(passwordEncoder.encode(rawSecret));
    clientRepository.save(client);
    auditService.log(actorId, AuditEventType.CLIENT_SECRET_ROTATED, "client", clientId, Map.of());
    return rawSecret;
  }
}
