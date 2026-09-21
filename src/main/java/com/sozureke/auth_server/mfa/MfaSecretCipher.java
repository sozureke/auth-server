package com.sozureke.auth_server.mfa;

import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.encrypt.AesGcmBytesEncryptor;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.stereotype.Component;

@Component
public class MfaSecretCipher {
  private static final int KEY_BYTES = 32;

  private final BytesEncryptor encryptor;

  public MfaSecretCipher(@Value("${app.mfa.encryption-key}") String base64Key) {
    byte[] key;
    try {
      key = Base64.getDecoder().decode(base64Key);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException("MFA_ENCRYPTION_KEY must be valid base64", e);
    }
    if (key.length != KEY_BYTES) {
      throw new IllegalStateException(
          "MFA_ENCRYPTION_KEY must decode to exactly 32 bytes, got " + key.length);
    }
    this.encryptor = AesGcmBytesEncryptor.withSecretKey(new SecretKeySpec(key, "AES")).build();
  }

  public String encrypt(byte[] secret) {
    return Base64.getEncoder().encodeToString(encryptor.encrypt(secret));
  }

  public byte[] decrypt(String stored) {
    if (stored == null || stored.isBlank()) {
      throw new MfaSecretException("Stored TOTP secret is empty", null);
    }
    try {
      byte[] plain = encryptor.decrypt(Base64.getDecoder().decode(stored));
      if (plain.length == 0) {
        throw new MfaSecretException("Decrypted TOTP secret is empty", null);
      }
      return plain;
    } catch (MfaSecretException e) {
      throw e;
    } catch (RuntimeException e) {
      throw new MfaSecretException("Unable to decrypt TOTP secret", e);
    }
  }
}
