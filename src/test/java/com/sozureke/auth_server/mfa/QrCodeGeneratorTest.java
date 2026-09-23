package com.sozureke.auth_server.mfa;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class QrCodeGeneratorTest {

  private static final String URI =
      "otpauth://totp/Auth%20Server:alice@example.com"
          + "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Auth%20Server";

  private final QrCodeGenerator generator = new QrCodeGenerator();

  @Test
  void png_decodesBackToExactlyTheOriginalContent() {
    assertThat(QrTestSupport.decode(generator.png(URI))).isEqualTo(URI);
  }

  @Test
  void png_isAValidPngImage() {
    byte[] png = generator.png(URI);

    assertThat(png[0]).isEqualTo((byte) 0x89);
    assertThat(new String(png, 1, 3, java.nio.charset.StandardCharsets.US_ASCII)).isEqualTo("PNG");
  }

  @Test
  void png_isCompact() {
    // 1-bit PNG: about 0.8 KB. RGB would be ~10 KB, which would bloat every enrollment response.
    assertThat(generator.png(URI).length).isLessThan(3_000);
  }

  @Test
  void pngDataUri_hasImagePrefix_andDecodesToTheOriginalContent() {
    String dataUri = generator.pngDataUri(URI);

    assertThat(dataUri).startsWith("data:image/png;base64,");
    assertThat(QrTestSupport.decodeDataUri(dataUri)).isEqualTo(URI);
  }

  @Test
  void png_keepsNonAsciiContentIntact() {
    String content = "otpauth://totp/Сервис:пользователь@example.com?secret=ABC&issuer=Сервис";

    assertThat(QrTestSupport.decode(generator.png(content))).isEqualTo(content);
  }
}
