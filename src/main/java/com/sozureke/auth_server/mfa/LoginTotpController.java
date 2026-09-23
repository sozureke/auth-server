package com.sozureke.auth_server.mfa;

import com.sozureke.auth_server.auth.AuthUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginTotpController {

  private final MfaService mfaService;
  private final RequestCache requestCache;

  public LoginTotpController(MfaService mfaService, RequestCache requestCache) {
    this.mfaService = mfaService;
    this.requestCache = requestCache;
  }

  @GetMapping("/login/totp")
  public ResponseEntity<String> form(CsrfToken csrfToken) {
    return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(page(csrfToken, null));
  }

  @PostMapping("/login/totp")
  public void verify(
      @AuthenticationPrincipal AuthUserDetails principal,
      @RequestParam String code,
      CsrfToken csrfToken,
      HttpServletRequest request,
      HttpServletResponse response)
      throws IOException {
    if (!mfaService.verifyLoginCode(principal.getUser(), code)) {
      response.setContentType(MediaType.TEXT_HTML_VALUE);
      response.getWriter().write(page(csrfToken, "Invalid or expired code"));
      return;
    }

    HttpSession session = request.getSession(true);
    MfaSession.markVerified(session);

    SavedRequest saved = requestCache.getRequest(request, response);
    response.sendRedirect(saved != null ? saved.getRedirectUrl() : request.getContextPath() + "/");
  }

  private static String page(CsrfToken csrfToken, String error) {
    String errorHtml = error == null ? "" : "<p style=\"color:red\">" + error + "</p>";
    return """
        <!DOCTYPE html>
        <html>
        <body>
        <h1>Enter your authenticator code</h1>
        %s
        <form method="post" action="/login/totp">
          <input type="hidden" name="%s" value="%s"/>
          <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus/>
          <button type="submit">Verify</button>
        </form>
        </body>
        </html>
        """
        .formatted(errorHtml, csrfToken.getParameterName(), csrfToken.getToken());
  }
}
