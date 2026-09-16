package com.sozureke.auth_server.user;

import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class UserControllerTest {

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository userRepository;

  @Test
  void register_returnsCreatedUser_withUnverifiedEmail() throws Exception {
    String email = "register-it@example.com";

    mockMvc
        .perform(
            post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {"email":"%s","password":"StrongPassword123!"}
                    """
                        .formatted(email)))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.email").value(email))
        .andExpect(jsonPath("$.emailVerified").value(false))
        .andExpect(jsonPath("$.id", notNullValue()));
  }

  @Test
  void register_returnsConflict_whenEmailAlreadyTaken() throws Exception {
    String email = "duplicate-it@example.com";
    userRepository.save(new User(email, "hashed-password"));

    mockMvc
        .perform(
            post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {"email":"%s","password":"StrongPassword123!"}
                    """
                        .formatted(email)))
        .andExpect(status().isConflict());
  }

  @Test
  void register_returnsBadRequest_whenPasswordTooWeak() throws Exception {
    mockMvc
        .perform(
            post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {"email":"weak-password-it@example.com","password":"weak"}
                    """))
        .andExpect(status().isBadRequest());
  }

  @Test
  void verifyEmail_marksUserVerified_whenTokenValid() throws Exception {
    User user = new User("verify-it@example.com", "hashed-password");
    user.setVerificationToken("valid-it-token");
    userRepository.save(user);

    mockMvc
        .perform(get("/auth/verify").param("token", "valid-it-token"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.emailVerified").value(true));
  }

  @Test
  void verifyEmail_returnsNotFound_whenTokenInvalid() throws Exception {
    mockMvc
        .perform(get("/auth/verify").param("token", "bad-token"))
        .andExpect(status().isNotFound());
  }
}
