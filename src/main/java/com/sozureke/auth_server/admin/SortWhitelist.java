package com.sozureke.auth_server.admin;

import java.util.Set;
import org.springframework.data.domain.Pageable;

final class SortWhitelist {

  private SortWhitelist() {}

  static void check(Pageable pageable, Set<String> allowed) {
    for (var order : pageable.getSort()) {
      if (!allowed.contains(order.getProperty())) {
        throw new InvalidSortException(order.getProperty());
      }
    }
  }
}
