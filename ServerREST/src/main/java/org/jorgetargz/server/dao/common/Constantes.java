package org.jorgetargz.server.dao.common;

public class Constantes {

    //Configuracion de la base de datos
    public static final String CACHE_PREP_STMTS = "cachePrepStmts";
    public static final String PREP_STMT_CACHE_SIZE = "prepStmtCacheSize";
    public static final String PREP_STMT_CACHE_SQL_LIMIT = "prepStmtCacheSqlLimit";
    public static final String CONNECTION_TO_DATABASE_ESTABLISHED = "Connection to database established";
    public static final String CLOSING_CONNECTION_POOL = "Closing connection pool";
    public static final int MAX_POOL_SIZE = 4;
    public static final int TIMEOUT_MS = 5000;
    public static final int CACHE_SIZE = 250;
    public static final int CACHE_SQL_LIMIT = 2048;

    //Column names for mapping tables
    public static final String ID = "id";
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";
    public static final String NAME = "name";
    public static final String WRITE_BY_ALL = "write";
    public static final String READ_BY_ALL = "read";
    public static final String IV = "iv";
    public static final String SALT = "salt";
    public static final String CIPHER_TEXT = "cipherText";
    public static final String ROLE = "role";
    public static final String CERTIFICATE = "certificate";

    //Exceptions messages
    public static final String LOGIN_NOT_FOUND = "Login not found";
    public static final String DATABASE_ERROR = "Database error";
    public static final String VAULT_NOT_FOUND = "Vault not found";
    public static final String MESSAGE_NOT_FOUND = "Message not found";


    private Constantes() {
    }

}