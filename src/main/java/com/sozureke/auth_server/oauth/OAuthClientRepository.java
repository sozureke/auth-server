package com.sozureke.auth_server.oauth;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuthClientRepository extends JpaRepository<OAuthClient, String> {
  Optional<OAuthClient> findByClientId(String clientId);
}
