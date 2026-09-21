package com.sozureke.auth_server.mfa;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.NotFoundException;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;
import javax.imageio.ImageIO;

final class QrTestSupport {
  private static final String DATA_URI_PREFIX = "data:image/png;base64,";

  private QrTestSupport() {}

  static String decode(byte[] png) {
    try {
      BufferedImage image = ImageIO.read(new ByteArrayInputStream(png));
      int width = image.getWidth();
      int height = image.getHeight();
      int[] pixels = image.getRGB(0, 0, width, height, null, 0, width);
      return new QRCodeReader()
          .decode(
              new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(width, height, pixels))))
          .getText();
    } catch (IOException
        | NotFoundException
        | com.google.zxing.ChecksumException
        | com.google.zxing.FormatException e) {
      throw new IllegalStateException("QR code could not be decoded", e);
    }
  }

  static String decodeDataUri(String dataUri) {
    if (!dataUri.startsWith(DATA_URI_PREFIX)) {
      throw new IllegalArgumentException("Not a PNG data URI");
    }
    return decode(Base64.getDecoder().decode(dataUri.substring(DATA_URI_PREFIX.length())));
  }
}
