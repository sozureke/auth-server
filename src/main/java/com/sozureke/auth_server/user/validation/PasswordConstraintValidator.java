package com.sozureke.auth_server.user.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordConstraintValidator implements ConstraintValidator<ValidPassword, String> {

    private static final int MIN_LENGTH = 12;

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null)
            return false;

        context.disableDefaultConstraintViolation();

        boolean valid = true;

        if (password.length() < MIN_LENGTH) {
            addViolation(context, "Password must be at least " + MIN_LENGTH + " characters long");
            valid = false;
        }
        if (!password.matches(".*[a-z].*")) {
            addViolation(context, "Password must contain at least one lowercase letter");
            valid = false;
        }
        if (!password.matches(".*[A-Z].*")) {
            addViolation(context, "Password must contain at least one uppercase letter");
            valid = false;
        }
        if (!password.matches(".*\\d.*")) {
            addViolation(context, "Password must contain at least one digit");
            valid = false;
        }
        if (!password.matches(".*[@$!%*?&#].*")) {
            addViolation(context, "Password must contain at least one special character (@$!%*?&#)");
            valid = false;
        }

        return valid;
    }

    private void addViolation(ConstraintValidatorContext context, String message) {
        context.buildConstraintViolationWithTemplate(message)
                .addConstraintViolation();
    }
}