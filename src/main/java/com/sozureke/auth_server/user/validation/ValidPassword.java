package com.sozureke.auth_server.user.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Target({ ElementType.FIELD, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PasswordConstraintValidator.class)
public @interface ValidPassword {

    String message() default "Password does not meet security requirements";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}