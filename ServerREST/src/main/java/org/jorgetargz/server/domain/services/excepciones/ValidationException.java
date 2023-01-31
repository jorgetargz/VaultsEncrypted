package org.jorgetargz.server.domain.services.excepciones;

public class ValidationException extends RuntimeException {
    public ValidationException(String message) {
        super(message);
    }
}
