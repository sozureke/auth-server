package com.sozureke.auth_server.user;

import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByEmail(String email);

  boolean existsByEmail(String email);

  Optional<User> findByVerificationToken(String verificationToken);

  Optional<User> findByResetToken(String resetToken);

  @Modifying
  @Query(
      "UPDATE User u SET u.mfaLastUsedInterval = :interval "
          + "WHERE u.id = :id AND u.mfaLastUsedInterval < :interval")
  int advanceMfaInterval(@Param("id") Long id, @Param("interval") long interval);

  @Query(
      """
      SELECT u FROM User u
      WHERE CAST(:pattern AS string) IS NULL
         OR LOWER(u.email) LIKE CAST(:pattern AS string) ESCAPE '\\'
      """)
  Page<User> search(@Param("pattern") String pattern, Pageable pageable);
}
