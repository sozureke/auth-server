package com.sozureke.auth_server.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class MfaSecretCipherTest {

  private static final String KEY_A = keyOf((byte) 1);
  private static final String KEY_B = keyOf((byte) 2);

  private static String keyOf(byte fill) {
    byte[] key = new byte[32];
    Arrays.fill(key, fill);
    return Base64.getEncoder().encodeToString(key);
  }

  private static byte[] secret() {
    byte[] secret = new byte[20];
    for (int i = 0; i < secret.length; i++) {
      secret[i] = (byte) (i * 7 + 3);
    }
    return secret;
  }

  @Test
  void encryptThenDecrypt_returnsOriginalSecret() {
    MfaSecretCipher cipher = new MfaSecretCipher(KEY_A);

    assertThat(cipher.decrypt(cipher.encrypt(secret()))).isEqualTo(secret());
  }

  @Test
  void encrypt_producesDifferentCiphertextEachTime() {
    MfaSecretCipher cipher = new MfaSecretCipher(KEY_A);

    assertThat(cipher.encrypt(secret())).isNotEqualTo(cipher.encrypt(secret()));
  }

  @Test
  void encrypt_doesNotLeakPlaintext() {
    MfaSecretCipher cipher = new MfaSecretCipher(KEY_A);
    byte[] cipherBytes = Base64.getDecoder().decode(cipher.encrypt(secret()));

    assertThat(cipherBytes).hasSize(52); // 16-byte IV + 20 bytes + 16-byte GCM tag
    assertThat(new String(cipherBytes, java.nio.charset.StandardCharsets.ISO_8859_1))
        .doesNotContain(new String(secret(), java.nio.charset.StandardCharsets.ISO_8859_1));
  }

  @Test
  void decrypt_failsWithWrongKey() {
    String stored = new MfaSecretCipher(KEY_A).encrypt(secret());

    assertThatThrownBy(() -> new MfaSecretCipher(KEY_B).decrypt(stored))
        .isInstanceOf(MfaSecretException.class);
  }

  @Test
  void decrypt_failsWhenAnyRegionIsTampered() {
    MfaSecretCipher cipher = new MfaSecretCipher(KEY_A);
    byte[] original = Base64.getDecoder().decode(cipher.encrypt(secret()));

    // IV, ciphertext body, and GCM tag: flipping one bit anywhere must be detected.
    for (int index : new int[] {0, 20, original.length - 1}) {
      byte[] tampered = original.clone();
      tampered[index] ^= 0x01;
      String stored = Base64.getEncoder().encodeToString(tampered);

      assertThatThrownBy(() -> cipher.decrypt(stored))
          .as("tampered byte %d", index)
          .isInstanceOf(MfaSecretException.class);
    }
  }

  @Test
  void decrypt_failsClosedOnNullBlankTruncatedAndNonBase64() {
    MfaSecretCipher cipher = new MfaSecretCipher(KEY_A);
    String truncated =
        Base64.getEncoder().encodeToString(Arrays.copyOf(new byte[] {1, 2, 3, 4, 5}, 5));

    for (String bad : new String[] {null, "", "   ", truncated, "!!!not-base64!!!"}) {
      assertThatThrownBy(() -> cipher.decrypt(bad))
          .as("stored=%s", bad)
          .isInstanceOf(MfaSecretException.class);
    }
  }

  @Test
  void decrypt_failsWhenDecryptedSecretIsEmpty() {
    MfaSecretCipher cipher = new MfaSecretCipher(KEY_A);
    String storedEmpty = cipher.encrypt(new byte[0]);

    assertThatThrownBy(() -> cipher.decrypt(storedEmpty)).isInstanceOf(MfaSecretException.class);
  }

  @Test
  void constructor_rejectsKeysThatAreNotBase64OrNot32Bytes() {
    String shortKey = Base64.getEncoder().encodeToString(new byte[16]);
    String longKey = Base64.getEncoder().encodeToString(new byte[64]);

    assertThatThrownBy(() -> new MfaSecretCipher("not base64 !!!"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("base64");
    assertThatThrownBy(() -> new MfaSecretCipher(shortKey))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("32 bytes");
    assertThatThrownBy(() -> new MfaSecretCipher(longKey))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("32 bytes");
    assertThatThrownBy(() -> new MfaSecretCipher("")).isInstanceOf(IllegalStateException.class);
  }

  @Test
  void constructor_errorMessageNeverContainsTheKey() {
    String badKey = Base64.getEncoder().encodeToString(new byte[16]);

    assertThatThrownBy(() -> new MfaSecretCipher(badKey)).hasMessageNotContaining(badKey);
  }
}
