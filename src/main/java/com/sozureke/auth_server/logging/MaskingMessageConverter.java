package com.sozureke.auth_server.logging;

import ch.qos.logback.classic.pattern.MessageConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import java.util.regex.Pattern;

public class MaskingMessageConverter extends MessageConverter {

  private static final String MASK = "***";

  private static final Pattern KEY_VALUE =
      Pattern.compile(
          "(?i)\\b(password|passwd|pwd|secret|client_secret|token|access_token|refresh_token"
              + "|id_token|code_verifier|totp|otp)([\"']?\\s*[:=]\\s*[\"']?)[^\\s\"'&,;}\\])]+");

  private static final Pattern AUTH_SCHEME =
      Pattern.compile("(?i)\\b(basic|bearer)\\s+[A-Za-z0-9._~+/=-]{8,}");

  private static final Pattern JWT =
      Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*");

  @Override
  public String convert(ILoggingEvent event) {
    return mask(super.convert(event));
  }

  public static String mask(String message) {
    if (message == null || message.isEmpty()) {
      return message;
    }
    String masked = JWT.matcher(message).replaceAll(MASK);
    masked = AUTH_SCHEME.matcher(masked).replaceAll("$1 " + MASK);
    return KEY_VALUE.matcher(masked).replaceAll("$1$2" + MASK);
  }
}
