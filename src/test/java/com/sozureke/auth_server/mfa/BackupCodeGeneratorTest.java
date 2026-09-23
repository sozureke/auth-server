package com.sozureke.auth_server.mfa;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class BackupCodeGeneratorTest {

  private static final String FORMAT =
      "^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}$";

  @Test
  void generate_returnsTenCodes() {
    assertThat(new BackupCodeGenerator().generate()).hasSize(10);
  }

  @Test
  void generate_codesAreUnique() {
    List<String> codes = new BackupCodeGenerator().generate();

    assertThat(Set.copyOf(codes)).hasSize(codes.size());
  }

  @Test
  void generate_codesMatchTheExpectedFormat() {
    for (String code : new BackupCodeGenerator().generate()) {
      assertThat(code).as("code=%s", code).matches(FORMAT);
    }
  }

  @Test
  void generate_neverProducesAmbiguousCharacters() {
    for (String code : new BackupCodeGenerator().generate()) {
      assertThat(code).as("code=%s", code).doesNotContainAnyWhitespaces();
      for (char ambiguous : new char[] {'0', 'O', '1', 'I'}) {
        assertThat(code.indexOf(ambiguous)).as("code=%s char=%s", code, ambiguous).isEqualTo(-1);
      }
    }
  }

  @Test
  void generate_successiveCallsProduceDifferentBatches() {
    BackupCodeGenerator generator = new BackupCodeGenerator();

    assertThat(generator.generate()).isNotEqualTo(generator.generate());
  }
}
