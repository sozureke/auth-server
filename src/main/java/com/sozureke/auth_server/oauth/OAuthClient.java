package com.sozureke.auth_server.oauth;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "oauth_clients")
@Getter
@Setter
@NoArgsConstructor
public class OAuthClient {

  @Id private String id;

  @Column(name = "client_id", nullable = false, unique = true)
  private String clientId;

  @Column(name = "client_secret", nullable = false)
  private String clientSecret;

  @Column(name = "client_name", nullable = false)
  private String clientName;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(
      name = "oauth_client_redirect_uris",
      joinColumns = @JoinColumn(name = "client_id"))
  @Column(name = "redirect_uri")
  private Set<String> redirectUris = new HashSet<>();

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "oauth_client_scopes", joinColumns = @JoinColumn(name = "client_id"))
  @Column(name = "scope")
  private Set<String> scopes = new HashSet<>();

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "oauth_client_grant_types", joinColumns = @JoinColumn(name = "client_id"))
  @Column(name = "grant_type")
  private Set<String> authorizationGrantTypes = new HashSet<>();

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(
      name = "oauth_client_auth_methods",
      joinColumns = @JoinColumn(name = "client_id"))
  @Column(name = "auth_method")
  private Set<String> clientAuthenticationMethods = new HashSet<>();

  @Column(name = "require_proof_key", nullable = false)
  private boolean requireProofKey = true;

  @Column(name = "created_at", nullable = false)
  private LocalDateTime createdAt;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @PrePersist
  protected void onCreate() {
    LocalDateTime now = LocalDateTime.now();
    createdAt = now;
    updatedAt = now;
  }

  @PreUpdate
  protected void onUpdate() {
    updatedAt = LocalDateTime.now();
  }
}
