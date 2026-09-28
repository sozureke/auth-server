package com.sozureke.auth_server.ratelimit;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Request whose body was fully read up front, so the rate limiter can look at it and the controller
 * can still read it. ContentCachingRequestWrapper can't do this: it only caches what downstream
 * code reads.
 */
class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

  private final byte[] body;

  CachedBodyHttpServletRequest(HttpServletRequest request, byte[] body) {
    super(request);
    this.body = body;
  }

  byte[] body() {
    return body;
  }

  @Override
  public ServletInputStream getInputStream() {
    ByteArrayInputStream source = new ByteArrayInputStream(body);
    return new ServletInputStream() {
      @Override
      public int read() {
        return source.read();
      }

      @Override
      public boolean isFinished() {
        return source.available() == 0;
      }

      @Override
      public boolean isReady() {
        return true;
      }

      @Override
      public void setReadListener(ReadListener listener) {
        throw new UnsupportedOperationException("async reads are not supported");
      }
    };
  }

  @Override
  public BufferedReader getReader() {
    String encoding = getCharacterEncoding();
    Charset charset = encoding != null ? Charset.forName(encoding) : StandardCharsets.UTF_8;
    return new BufferedReader(new InputStreamReader(getInputStream(), charset));
  }
}
