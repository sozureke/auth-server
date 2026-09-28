package com.sozureke.auth_server.admin;

import com.sozureke.auth_server.admin.dto.AdminSessionSummary;
import com.sozureke.auth_server.util.Sha256;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;

@Service
public class AdminSessionService {

  private static final String INDEX_MARKER =
      "index:" + FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME + ":";

  private final StringRedisTemplate redisTemplate;
  private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;

  public AdminSessionService(
      StringRedisTemplate redisTemplate,
      FindByIndexNameSessionRepository<? extends Session> sessionRepository) {
    this.redisTemplate = redisTemplate;
    this.sessionRepository = sessionRepository;
  }

  public Page<AdminSessionSummary> list(Pageable pageable) {
    List<AdminSessionSummary> all = new ArrayList<>();
    for (String principal : principals()) {
      sessionRepository
          .findByPrincipalName(principal)
          .forEach((id, session) -> all.add(toSummary(principal, id, session)));
    }
    all.sort(Comparator.comparing(AdminSessionSummary::lastAccessedAt).reversed());

    int from = (int) Math.min(pageable.getOffset(), all.size());
    int to = Math.min(from + pageable.getPageSize(), all.size());
    return new PageImpl<>(all.subList(from, to), pageable, all.size());
  }

  public long count() {
    long total = 0;
    for (String principal : principals()) {
      total += sessionRepository.findByPrincipalName(principal).size();
    }
    return total;
  }

  private Set<String> principals() {
    Set<String> principals = new TreeSet<>();
    ScanOptions options =
        ScanOptions.scanOptions().match("*" + INDEX_MARKER + "*").count(500).build();
    try (Cursor<String> cursor = redisTemplate.scan(options)) {
      while (cursor.hasNext()) {
        String key = cursor.next();
        int marker = key.indexOf(INDEX_MARKER);
        if (marker >= 0) {
          principals.add(key.substring(marker + INDEX_MARKER.length()));
        }
      }
    }
    return principals;
  }

  private static AdminSessionSummary toSummary(String principal, String id, Session session) {
    return new AdminSessionSummary(
        Sha256.hex(id),
        principal,
        session.getAttribute("ipAddress"),
        session.getAttribute("userAgent"),
        session.getCreationTime(),
        session.getLastAccessedTime());
  }
}
