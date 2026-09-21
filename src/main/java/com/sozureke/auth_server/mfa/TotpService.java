package com.sozureke.auth_server.mfa;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.OptionalLong;
import java.util.regex.Pattern;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriUtils;

@Service
public class TotpService {
  private static final Logger log = LoggerFactory.getLogger(TotpService.class);
  private static final Pattern CODE = Pattern.compile("^\\d{6}$");

  private final Clock clock;
  private final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();
  private final long stepSeconds = totp.getTimeStep().getSeconds();
  private final Base32 base32 = new Base32();

  public TotpService(Clock clock) {
    this.clock = clock;
  }

  public byte[] generateSecret() {
    try {
      KeyGenerator generator = KeyGenerator.getInstance(totp.getAlgorithm());
      generator.init(160);
      return generator.generateKey().getEncoded();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  public String encodeSecret(byte[] secret) {
    return base32.encodeToString(secret);
  }

  public String otpauthUri(String issuer, String account, byte[] secret) {
    String label = UriUtils.encodePathSegment(issuer + ":" + account, StandardCharsets.UTF_8);
    return "otpauth://totp/%s?secret=%s&issuer=%s"
        .formatted(
            label,
            base32.encodeToString(secret),
            UriUtils.encodeQueryParam(issuer, StandardCharsets.UTF_8));
  }

  public OptionalLong verify(byte[] secret, String code, long lastUsedInterval) {
    if (code == null || !CODE.matcher(code).matches()) {
      return OptionalLong.empty();
    }
    if (secret == null || secret.length == 0) {
      log.error("TOTP verification requested with an empty secret — refusing");
      return OptionalLong.empty();
    }

    SecretKey key = new SecretKeySpec(secret, totp.getAlgorithm());
    byte[] given = code.getBytes(StandardCharsets.UTF_8);
    long current = clock.instant().getEpochSecond() / stepSeconds;

    try {
      for (long interval = current; interval >= current - 1; interval--) {
        if (interval <= lastUsedInterval) {
          continue;
        }
        String expected =
            totp.generateOneTimePasswordString(key, Instant.ofEpochSecond(interval * stepSeconds));
        if (MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), given)) {
          return OptionalLong.of(interval);
        }
      }
    } catch (InvalidKeyException e) {
      throw new IllegalStateException("Invalid TOTP key", e);
    }
    return OptionalLong.empty();
  }
}
