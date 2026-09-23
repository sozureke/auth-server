package com.sozureke.auth_server.mfa;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;
import javax.imageio.ImageIO;
import org.springframework.stereotype.Component;

@Component
public class QrCodeGenerator {
  private static final int SIZE = 300;

  public byte[] png(String content) {
    try {
      Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
      hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
      hints.put(EncodeHintType.MARGIN, 2);
      hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");

      BitMatrix matrix =
          new QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, SIZE, SIZE, hints);
      // 1-bit PNG: ~0.8 KB instead of ~10 KB for RGB
      BufferedImage image =
          new BufferedImage(matrix.getWidth(), matrix.getHeight(), BufferedImage.TYPE_BYTE_BINARY);
      for (int x = 0; x < matrix.getWidth(); x++) {
        for (int y = 0; y < matrix.getHeight(); y++) {
          image.setRGB(x, y, matrix.get(x, y) ? 0xFF000000 : 0xFFFFFFFF);
        }
      }
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ImageIO.write(image, "png", out);
      return out.toByteArray();
    } catch (WriterException | IOException e) {
      throw new IllegalStateException("Unable to generate QR code", e);
    }
  }

  public String pngDataUri(String content) {
    return "data:image/png;base64," + Base64.getEncoder().encodeToString(png(content));
  }
}
