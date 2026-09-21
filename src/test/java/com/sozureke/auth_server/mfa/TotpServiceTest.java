package com.sozureke.auth_server.mfa;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;

class TotpServiceTest {

  // RFC 6238 Appendix B (SHA-1): the shared secret is the ASCII string "12345678901234567890".
  private static final byte[] RFC_SECRET =
      "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
  private static final String RFC_SECRET_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

  // 0 mirrors the DB default: real intervals are ~41M, so 0 means "never used".
  private static final long NEVER_USED = 0L;

  // Reference point: T=1234567890 -> interval 41152263, whose code is 005924.
  private static final long NOW = 1234567890L;
  private static final long NOW_INTERVAL = 41152263L;
  private static final String CODE_NOW = "005924";
  private static final String CODE_PREVIOUS = "980357"; // interval 41152262
  private static final String CODE_TWO_BACK = "186057"; // interval 41152261
  private static final String CODE_NEXT = "590587"; // interval 41152264

  private static TotpService serviceAt(long epochSeconds) {
    return new TotpService(Clock.fixed(Instant.ofEpochSecond(epochSeconds), ZoneOffset.UTC));
  }

  @Test
  void verify_matchesRfc6238Vectors() {
    assertThat(serviceAt(59).verify(RFC_SECRET, "287082", NEVER_USED)).hasValue(1L);
    assertThat(serviceAt(1111111109L).verify(RFC_SECRET, "081804", NEVER_USED)).hasValue(37037036L);
    assertThat(serviceAt(NOW).verify(RFC_SECRET, CODE_NOW, NEVER_USED)).hasValue(NOW_INTERVAL);
  }

  @Test
  void verify_acceptsCodeWithLeadingZeros() {
    assertThat(serviceAt(NOW).verify(RFC_SECRET, "005924", NEVER_USED)).isPresent();
  }

  @Test
  void verify_acceptsPreviousInterval() {
    assertThat(serviceAt(NOW).verify(RFC_SECRET, CODE_PREVIOUS, NEVER_USED))
        .hasValue(NOW_INTERVAL - 1);
  }

  @Test
  void verify_rejectsTwoIntervalsBack() {
    assertThat(serviceAt(NOW).verify(RFC_SECRET, CODE_TWO_BACK, NEVER_USED)).isEmpty();
  }

  @Test
  void verify_rejectsFutureInterval() {
    assertThat(serviceAt(NOW).verify(RFC_SECRET, CODE_NEXT, NEVER_USED)).isEmpty();
  }

  @Test
  void verify_rejectsReplayOfSameInterval() {
    TotpService service = serviceAt(NOW);
    OptionalLong first = service.verify(RFC_SECRET, CODE_NOW, NEVER_USED);

    assertThat(first).hasValue(NOW_INTERVAL);
    assertThat(service.verify(RFC_SECRET, CODE_NOW, first.getAsLong())).isEmpty();
  }

  @Test
  void verify_rejectsOlderIntervalOnceNewerWasUsed() {
    assertThat(serviceAt(NOW).verify(RFC_SECRET, CODE_PREVIOUS, NOW_INTERVAL)).isEmpty();
  }

  @Test
  void verify_acceptsPreviousIntervalWhenNothingNewerWasUsed() {
    assertThat(serviceAt(NOW).verify(RFC_SECRET, CODE_PREVIOUS, NOW_INTERVAL - 2))
        .hasValue(NOW_INTERVAL - 1);
  }

  @Test
  void verify_rejectsMalformedCodesWithoutThrowing() {
    TotpService service = serviceAt(NOW);

    for (String bad :
        new String[] {
          null, "", "abc", "5924", "1234567", " 005924", "005924 ", "00592a", "٠٠٥٩٢٤"
        }) {
      assertThat(service.verify(RFC_SECRET, bad, NEVER_USED)).as("code=%s", bad).isEmpty();
    }
  }

  @Test
  void verify_rejectsWrongCode() {
    assertThat(serviceAt(NOW).verify(RFC_SECRET, "000000", NEVER_USED)).isEmpty();
  }

  @Test
  void verify_failsClosedOnMissingOrEmptySecret() {
    TotpService service = serviceAt(NOW);

    assertThat(service.verify(null, CODE_NOW, NEVER_USED)).isEmpty();
    assertThat(service.verify(new byte[0], CODE_NOW, NEVER_USED)).isEmpty();
  }

  @Test
  void verify_rejectsCodeGeneratedForDifferentSecret() {
    byte[] otherSecret = "ABCDEFGHIJKLMNOPQRST".getBytes(StandardCharsets.US_ASCII);

    assertThat(serviceAt(NOW).verify(otherSecret, CODE_NOW, NEVER_USED)).isEmpty();
  }

  @Test
  void generateSecret_returns160BitSecretsThatDiffer() {
    TotpService service = serviceAt(NOW);

    byte[] first = service.generateSecret();
    byte[] second = service.generateSecret();

    assertThat(first).hasSize(20);
    assertThat(second).hasSize(20);
    assertThat(first).isNotEqualTo(second);
  }

  @Test
  void generatedSecret_roundTripsThroughVerify() {
    TotpService service = serviceAt(NOW);
    byte[] secret = service.generateSecret();

    // A code produced for the same secret at the same instant must be accepted:
    // compute it via a second service on the same clock and the library's own generator.
    String code = codeFor(secret, NOW);

    assertThat(service.verify(secret, code, NEVER_USED)).hasValue(NOW_INTERVAL);
  }

  @Test
  void otpauthUri_containsIssuerAndBase32SecretAndEncodesSpaces() {
    String uri = serviceAt(NOW).otpauthUri("Auth Server", "alice@example.com", RFC_SECRET);

    assertThat(uri)
        .startsWith("otpauth://totp/Auth%20Server:alice@example.com?")
        .contains("secret=" + RFC_SECRET_BASE32)
        .contains("issuer=Auth%20Server")
        .doesNotContain("+");
  }

  private static String codeFor(byte[] secret, long epochSeconds) {
    try {
      var totp = new com.eatthepath.otp.TimeBasedOneTimePasswordGenerator();
      var key = new javax.crypto.spec.SecretKeySpec(secret, totp.getAlgorithm());
      return totp.generateOneTimePasswordString(key, Instant.ofEpochSecond(epochSeconds));
    } catch (java.security.InvalidKeyException e) {
      throw new IllegalStateException(e);
    }
  }
}
