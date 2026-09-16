package com.sozureke.auth_server.user;

import java.util.Optional;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.sozureke.auth_server.config.InvalidVerificationTokenException;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User register(String email, String rawPassword) {
        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException(email);
        }

        String passwordHash = passwordEncoder.encode(rawPassword);

        User user = new User(email, passwordHash);

        user.setVerificationToken(UUID.randomUUID().toString());
        user.setCreatedAt(java.time.LocalDateTime.now());
        user.setUpdatedAt(java.time.LocalDateTime.now());

        User savedUser = userRepository.save(user);

        System.out.println("Verification link: /auth/verify?token=" + savedUser.getVerificationToken());
        return savedUser;
    }

    public User verifyEmail(String token) {
        Optional<User> userResult = userRepository.findByVerificationToken(token);
        if (userResult.isEmpty())
            throw new InvalidVerificationTokenException(token);

        User user = userResult.get();

        user.setEmailVerified(true);
        user.setVerificationToken(null);
        user.setUpdatedAt(java.time.LocalDateTime.now());

        return userRepository.save(user);
    }
}
