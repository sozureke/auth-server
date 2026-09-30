package com.sozureke.auth_server.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sozureke.auth_server.role.RoleRepository;
import com.sozureke.auth_server.user.User;
import com.sozureke.auth_server.user.UserRepository;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
class OAuthFlowE2ETest {

  private static final String PASSWORD = "Str0ng!Passw0rd#2026";
  private static final String CLIENT_SECRET = "client-secret-for-e2e";
  private static final String REDIRECT_URI = "http://127.0.0.1:8081/callback";

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;
  @Autowired private RoleRepository roleRepository;
  @Autowired private RegisteredClientRepository clientRepository;
  @Autowired private PasswordEncoder passwordEncoder;
  @Autowired private JwtDecoder jwtDecoder;
  @Autowired private ObjectMapper objectMapper;

  private final String tag = UUID.randomUUID().toString().substring(0, 8);
  private final String clientIp = randomIp();
  private String email;
  private String clientId;
  private String otherClientId;

  @BeforeEach
  void setUp() {
    email = "oauth-e2e-" + tag + "@example.com";
    User user = new User(email, passwordEncoder.encode(PASSWORD));
    user.setEmailVerified(true);
    user.getRoles().add(roleRepository.findByName("USER").orElseThrow());
    userRepository.save(user);

    clientId = "e2e-client-" + tag;
    otherClientId = "e2e-other-" + tag;
    clientRepository.save(client(clientId));
    clientRepository.save(client(otherClientId));
  }

  private RegisteredClient client(String id) {
    return RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId(id)
        .clientSecret(passwordEncoder.encode(CLIENT_SECRET))
        .clientName(id)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .redirectUri(REDIRECT_URI)
        .scope("openid")
        .scope("profile")
        .clientSettings(ClientSettings.builder().requireProofKey(true).build())
        .build();
  }

  @Test
  void authorizationCodeFlowWithPkce_issuesVerifiableTokens_thatRefreshRotateAndRevoke()
      throws Exception {
    Cookie session = login();
    String verifier = codeVerifier();

    String code = authorize(session, clientId, challenge(verifier));
    JsonNode tokens = exchange(clientId, code, verifier);

    assertThat(tokens.path("token_type").asString()).isEqualTo("Bearer");
    assertThat(tokens.path("scope").asString()).contains("openid", "profile");
    assertThat(tokens.path("id_token").asString()).isNotBlank();

    Jwt accessToken = jwtDecoder.decode(tokens.path("access_token").asString());
    assertThat(accessToken.getSubject()).isEqualTo(email);
    assertThat(accessToken.getAudience()).containsExactly(clientId);
    assertThat(accessToken.getClaimAsStringList("roles")).containsExactly("USER");
    assertThat(accessToken.getExpiresAt())
        .isBefore(accessToken.getIssuedAt().plusSeconds(15 * 60 + 1));

    Jwt idToken = jwtDecoder.decode(tokens.path("id_token").asString());
    assertThat(idToken.getSubject()).isEqualTo(email);

    assertThat(introspect(tokens.path("access_token").asString()).path("active").asBoolean())
        .isTrue();

    String firstRefresh = tokens.path("refresh_token").asString();
    JsonNode refreshed = refresh(clientId, firstRefresh);
    assertThat(refreshed.path("access_token").asString()).isNotBlank();
    String secondRefresh = refreshed.path("refresh_token").asString();
    assertThat(secondRefresh).isNotBlank().isNotEqualTo(firstRefresh);

    MockHttpServletResponse reuse =
        token(clientId, "grant_type=refresh_token", "refresh_token=" + firstRefresh);
    assertThat(reuse.getStatus()).isEqualTo(400);
    assertThat(reuse.getContentAsString()).contains("invalid_grant");

    String accessToRevoke = refreshed.path("access_token").asString();
    assertThat(
            mockMvc
                .perform(
                    post("/oauth2/revoke")
                        .param("token", accessToRevoke)
                        .with(httpBasic(clientId, CLIENT_SECRET))
                        .with(fromIp()))
                .andReturn()
                .getResponse()
                .getStatus())
        .isEqualTo(200);
    assertThat(introspect(accessToRevoke).path("active").asBoolean()).isFalse();
  }

  @Test
  void authorizationCode_cannotBeRedeemedTwice() throws Exception {
    String verifier = codeVerifier();
    String code = authorize(login(), clientId, challenge(verifier));
    exchange(clientId, code, verifier);

    MockHttpServletResponse second = redeem(clientId, code, verifier);

    assertThat(second.getStatus()).isEqualTo(400);
    assertThat(second.getContentAsString()).contains("invalid_grant");
  }

  @Test
  void authorizationCode_withWrongPkceVerifier_isRejected() throws Exception {
    String code = authorize(login(), clientId, challenge(codeVerifier()));

    MockHttpServletResponse response = redeem(clientId, code, codeVerifier());

    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(response.getContentAsString()).contains("invalid_grant");
  }

  @Test
  void authorizationCode_issuedToOneClient_cannotBeRedeemedByAnother() throws Exception {
    String verifier = codeVerifier();
    String code = authorize(login(), clientId, challenge(verifier));

    MockHttpServletResponse response = redeem(otherClientId, code, verifier);

    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(response.getContentAsString()).contains("invalid_grant");
  }

  @Test
  void authorize_withoutPkce_isRejected_andIssuesNoCode() throws Exception {
    MockHttpServletResponse response =
        mockMvc
            .perform(authorizeRequest(clientId, REDIRECT_URI, null).cookie(login()))
            .andReturn()
            .getResponse();

    String location = response.getHeader(HttpHeaders.LOCATION);
    assertThat(location).doesNotContain("code=");
    assertThat(location).contains("error=invalid_request");
  }

  @Test
  void authorize_withUnregisteredRedirectUri_neverRedirectsToIt() throws Exception {
    MockHttpServletResponse response =
        mockMvc
            .perform(
                authorizeRequest(
                        clientId, "https://attacker.example.com/steal", challenge(codeVerifier()))
                    .cookie(login()))
            .andReturn()
            .getResponse();

    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(String.valueOf(response.getHeader(HttpHeaders.LOCATION)))
        .doesNotContain("attacker.example.com");
  }

  @Test
  void authorize_withoutLogin_redirectsBrowserToLogin_andRejectsOthers() throws Exception {
    MockHttpServletResponse browser =
        mockMvc
            .perform(
                authorizeRequest(clientId, REDIRECT_URI, challenge(codeVerifier()))
                    .header(HttpHeaders.ACCEPT, "text/html"))
            .andReturn()
            .getResponse();
    assertThat(browser.getStatus()).isEqualTo(302);
    assertThat(browser.getHeader(HttpHeaders.LOCATION)).endsWith("/login");

    MockHttpServletResponse api =
        mockMvc
            .perform(authorizeRequest(clientId, REDIRECT_URI, challenge(codeVerifier())))
            .andReturn()
            .getResponse();
    assertThat(api.getStatus()).isEqualTo(401);
    assertThat(String.valueOf(api.getHeader(HttpHeaders.LOCATION))).doesNotContain("code=");
  }

  @Test
  void tokenEndpoint_withWrongClientSecret_isUnauthorized() throws Exception {
    MockHttpServletResponse response =
        mockMvc
            .perform(
                post("/oauth2/token")
                    .param("grant_type", "authorization_code")
                    .param("code", "whatever")
                    .with(httpBasic(clientId, "wrong-secret"))
                    .with(fromIp()))
            .andReturn()
            .getResponse();

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getContentAsString()).contains("invalid_client");
  }

  @Test
  void tamperedAccessToken_isRejectedByTheDecoder_andIsNotActive() throws Exception {
    String verifier = codeVerifier();
    String accessToken =
        exchange(clientId, authorize(login(), clientId, challenge(verifier)), verifier)
            .path("access_token")
            .asString();

    String[] parts = accessToken.split("\\.");
    String payload =
        new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8)
            .replace("\"USER\"", "\"ADMIN\"");
    assertThat(payload).contains("\"ADMIN\"");
    String tampered =
        parts[0] + "." + base64Url(payload.getBytes(StandardCharsets.UTF_8)) + "." + parts[2];

    assertThatThrownBy(() -> jwtDecoder.decode(tampered)).isInstanceOf(JwtException.class);
    assertThat(introspect(tampered).path("active").asBoolean()).isFalse();
  }

  @Test
  void unsignedAlgNoneToken_isRejected() {
    String header = base64Url("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
    String payload =
        base64Url(
            ("{\"sub\":\"" + email + "\",\"roles\":[\"ADMIN\"],\"exp\":9999999999}")
                .getBytes(StandardCharsets.UTF_8));

    assertThatThrownBy(() -> jwtDecoder.decode(header + "." + payload + "."))
        .isInstanceOf(JwtException.class);
  }

  @Test
  void tokenSignedWithAForeignKey_isRejected() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    SignedJWT forged =
        new SignedJWT(
            new JWSHeader(JWSAlgorithm.RS256),
            new JWTClaimsSet.Builder()
                .subject(email)
                .claim("roles", List.of("ADMIN"))
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 60_000))
                .build());
    forged.sign(new RSASSASigner((RSAPrivateKey) generator.generateKeyPair().getPrivate()));

    assertThatThrownBy(() -> jwtDecoder.decode(forged.serialize()))
        .isInstanceOf(JwtException.class);
  }

  private Cookie login() throws Exception {
    MockHttpServletResponse response =
        mockMvc
            .perform(
                post("/login")
                    .param("username", email)
                    .param("password", PASSWORD)
                    .with(csrf())
                    .with(fromIp()))
            .andReturn()
            .getResponse();
    assertThat(response.getStatus()).isEqualTo(302);
    assertThat(response.getHeader(HttpHeaders.LOCATION)).doesNotContain("error");
    Cookie session = response.getCookie("SESSION");
    assertThat(session).isNotNull();
    return session;
  }

  private String authorize(Cookie session, String client, String challenge) throws Exception {
    MockHttpServletResponse response =
        mockMvc
            .perform(authorizeRequest(client, REDIRECT_URI, challenge).cookie(session))
            .andReturn()
            .getResponse();
    assertThat(response.getStatus())
        .as(response.getErrorMessage() + " " + response.getContentAsString())
        .isEqualTo(302);
    String location = response.getHeader(HttpHeaders.LOCATION);
    assertThat(location).startsWith(REDIRECT_URI);
    var query = UriComponentsBuilder.fromUriString(location).build().getQueryParams();
    assertThat(query.getFirst("state")).isEqualTo("state-" + tag);
    return java.net.URLDecoder.decode(query.getFirst("code"), StandardCharsets.UTF_8);
  }

  private MockHttpServletRequestBuilder authorizeRequest(
      String client, String redirectUri, String challenge) {
    UriComponentsBuilder uri =
        UriComponentsBuilder.fromPath("/oauth2/authorize")
            .queryParam("response_type", "code")
            .queryParam("client_id", client)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("scope", "openid profile")
            .queryParam("state", "state-" + tag);
    if (challenge != null) {
      uri.queryParam("code_challenge", challenge).queryParam("code_challenge_method", "S256");
    }
    return get(uri.encode().build().toUri());
  }

  private JsonNode exchange(String client, String code, String verifier) throws Exception {
    MockHttpServletResponse response = redeem(client, code, verifier);
    assertThat(response.getStatus()).as(response.getContentAsString()).isEqualTo(200);
    return objectMapper.readTree(response.getContentAsString());
  }

  private MockHttpServletResponse redeem(String client, String code, String verifier)
      throws Exception {
    return token(
        client,
        "grant_type=authorization_code",
        "code=" + code,
        "redirect_uri=" + REDIRECT_URI,
        "code_verifier=" + verifier);
  }

  private JsonNode refresh(String client, String refreshToken) throws Exception {
    MockHttpServletResponse response =
        token(client, "grant_type=refresh_token", "refresh_token=" + refreshToken);
    assertThat(response.getStatus()).as(response.getContentAsString()).isEqualTo(200);
    return objectMapper.readTree(response.getContentAsString());
  }

  private MockHttpServletResponse token(String client, String... params) throws Exception {
    MockHttpServletRequestBuilder request =
        post("/oauth2/token").with(httpBasic(client, CLIENT_SECRET)).with(fromIp());
    for (String param : params) {
      int eq = param.indexOf('=');
      request.param(param.substring(0, eq), param.substring(eq + 1));
    }
    return mockMvc.perform(request).andReturn().getResponse();
  }

  private JsonNode introspect(String token) throws Exception {
    return objectMapper.readTree(
        mockMvc
            .perform(
                post("/oauth2/introspect")
                    .param("token", token)
                    .with(httpBasic(clientId, CLIENT_SECRET))
                    .with(fromIp()))
            .andReturn()
            .getResponse()
            .getContentAsString());
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

  private static String codeVerifier() {
    byte[] bytes = new byte[32];
    new SecureRandom().nextBytes(bytes);
    return base64Url(bytes);
  }

  private static String challenge(String verifier) throws Exception {
    return base64Url(
        MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
  }

  private static String base64Url(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
