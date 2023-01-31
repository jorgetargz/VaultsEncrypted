package org.jorgetargz.server.dao.excepciones;

public class DatabaseException extends RuntimeException {
    public DatabaseException(String message) {
        super(message);
    }
}
