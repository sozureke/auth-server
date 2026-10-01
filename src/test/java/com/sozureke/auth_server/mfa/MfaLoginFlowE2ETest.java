package com.sozureke.auth_server.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.sozureke.auth_server.role.RoleRepository;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import jakarta.servlet.http.Cookie;
import java.net.URI;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.util.UriComponentsBuilder;

@SpringBootTest
@AutoConfigureMockMvc
class MfaLoginFlowE2ETest {

  private static final String PASSWORD = "Str0ng!Passw0rd#2026";
  private static final String REDIRECT_URI = "http://127.0.0.1:8081/callback";
  private static final String BACKUP_CODE = "ABCD2345EF";

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private RoleRepository roleRepository;
  @Autowired private BackupCodeRepository backupCodeRepository;
  @Autowired private RegisteredClientRepository clientRepository;
  @Autowired private PasswordEncoder passwordEncoder;
  @Autowired private MfaSecretCipher cipher;
  @Autowired private TotpService totpService;

  private final String tag = UUID.randomUUID().toString().substring(0, 8);
  private final String clientIp = randomIp();
  private String clientId;

  @BeforeEach
  void registerClient() {
    clientId = "mfa-e2e-" + tag;
    clientRepository.save(
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientSecret(passwordEncoder.encode("secret"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(REDIRECT_URI)
            .scope("openid")
            .clientSettings(ClientSettings.builder().requireProofKey(true).build())
            .build());
  }

  private User user(String label, String role) {
    User user =
        new User("mfa-e2e-" + label + "-" + tag + "@example.com", passwordEncoder.encode(PASSWORD));
    user.setEmailVerified(true);
    user.getRoles().add(roleRepository.findByName(role).orElseThrow());
    return userRepository.save(user);
  }

  private byte[] enrollMfa(User user) {
    byte[] secret = totpService.generateSecret();
    user.setTotpSecret(cipher.encrypt(secret));
    user.setMfaEnabled(true);
    userRepository.save(user);
    backupCodeRepository.save(new BackupCode(user.getId(), passwordEncoder.encode(BACKUP_CODE)));
    return secret;
  }

  private static String currentCode(byte[] secret) throws Exception {
    TimeBasedOneTimePasswordGenerator generator = new TimeBasedOneTimePasswordGenerator();
    return generator.generateOneTimePasswordString(
        new SecretKeySpec(secret, generator.getAlgorithm()), Instant.now());
  }

  @Test
  void userWithoutMfa_getsACodeRightAfterThePassword() throws Exception {
    User plain = user("plain", "USER");

    MockHttpServletResponse response = authorize(login(plain));

    assertThat(redirectTarget(response)).startsWith(REDIRECT_URI).contains("code=");
  }

  @Test
  void userWithMfa_mustPassTotp_beforeACodeIsIssued() throws Exception {
    User user = user("enrolled", "USER");
    byte[] secret = enrollMfa(user);
    Cookie session = login(user);

    MockHttpServletResponse challenged = authorize(session);
    assertThat(redirectTarget(challenged)).endsWith("/login/totp").doesNotContain("code=");

    MockHttpServletResponse wrong = submitTotp(session, "000000");
    assertThat(wrong.getStatus()).isEqualTo(200);
    assertThat(wrong.getContentAsString()).contains("Invalid or expired code");
    assertThat(redirectTarget(authorize(session))).endsWith("/login/totp");

    MockHttpServletResponse verified = submitTotp(session, currentCode(secret));
    String resumed = redirectTarget(verified);
    assertThat(resumed).contains("/oauth2/authorize");

    MockHttpServletResponse issued =
        mockMvc.perform(get(URI.create(resumed)).cookie(session)).andReturn().getResponse();
    assertThat(redirectTarget(issued)).startsWith(REDIRECT_URI).contains("code=");
  }

  @Test
  void totpCode_cannotBeReplayedInAnotherSession() throws Exception {
    User user = user("replay", "USER");
    byte[] secret = enrollMfa(user);
    String code = currentCode(secret);

    Cookie first = login(user);
    authorize(first);
    assertThat(redirectTarget(submitTotp(first, code))).contains("/oauth2/authorize");

    Cookie second = login(user);
    authorize(second);
    assertThat(submitTotp(second, code).getContentAsString()).contains("Invalid or expired code");
  }

  @Test
  void backupCode_works_exactlyOnce() throws Exception {
    User user = user("backup", "USER");
    enrollMfa(user);

    Cookie first = login(user);
    authorize(first);
    assertThat(redirectTarget(submitTotp(first, BACKUP_CODE))).contains("/oauth2/authorize");

    Cookie second = login(user);
    authorize(second);
    assertThat(submitTotp(second, BACKUP_CODE).getContentAsString())
        .contains("Invalid or expired code");
  }

  @Test
  void adminWithoutMfa_isRefused() throws Exception {
    User admin = user("admin-plain", "ADMIN");

    MockHttpServletResponse response = authorize(login(admin));

    assertThat(response.getStatus()).isEqualTo(403);
    assertThat(response.getContentAsString())
        .contains("MFA enrollment is required for admin accounts");
  }

  @Test
  void adminWithMfa_isChallenged() throws Exception {
    User admin = user("admin-enrolled", "ADMIN");
    enrollMfa(admin);

    assertThat(redirectTarget(authorize(login(admin)))).endsWith("/login/totp");
  }

  private Cookie login(User user) throws Exception {
    MockHttpServletResponse response =
        mockMvc
            .perform(
                post("/login")
                    .param("username", user.getEmail())
                    .param("password", PASSWORD)
                    .with(csrf())
                    .with(fromIp()))
            .andReturn()
            .getResponse();
    assertThat(response.getHeader(HttpHeaders.LOCATION)).doesNotContain("error");
    return response.getCookie("SESSION");
  }

  private MockHttpServletResponse authorize(Cookie session) throws Exception {
    URI uri =
        UriComponentsBuilder.fromPath("/oauth2/authorize")
            .queryParam("response_type", "code")
            .queryParam("client_id", clientId)
            .queryParam("redirect_uri", REDIRECT_URI)
            .queryParam("scope", "openid")
            .queryParam("state", "s")
            .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .queryParam("code_challenge_method", "S256")
            .encode()
            .build()
            .toUri();
    return mockMvc.perform(get(uri).cookie(session)).andReturn().getResponse();
  }

  private MockHttpServletResponse submitTotp(Cookie session, String code) throws Exception {
    MockHttpServletRequestBuilder request =
        post("/login/totp").cookie(session).param("code", code).with(csrf()).with(fromIp());
    return mockMvc.perform(request).andReturn().getResponse();
  }

  private static String redirectTarget(MockHttpServletResponse response) {
    assertThat(response.getStatus()).as(String.valueOf(response.getStatus())).isEqualTo(302);
    return response.getHeader(HttpHeaders.LOCATION);
  }

  private RequestPostProcessor fromIp() {
    return request -> {
      request.setRemoteAddr(clientIp);
      return request;
    };
  }

  private static String randomIp() {
    ThreadLocalRandom random = ThreadLocalRandom.current();
    return "10."
        + random.nextInt(256)
        + "."
        + random.nextInt(256)
        + "."
        + (1 + random.nextInt(254));
  }
}
