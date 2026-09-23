package com.sozureke.auth_server.mfa;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface BackupCodeRepository extends JpaRepository<BackupCode, Long> {
  List<BackupCode> findByUserIdAndUsedFalse(Long userId);

  void deleteByUserId(Long userId);

  @Modifying
  @Query("UPDATE BackupCode b SET b.used = true WHERE b.id = :id AND b.used = false")
  int markUsed(@Param("id") Long id);
}
