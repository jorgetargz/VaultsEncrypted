package org.jorgetargz.server.jakarta.common;

public class Constantes {

    public static final String CERTIFICATE = "Certificate";

    private Constantes() {
    }



    public static final String TOKEN_IN_BLACK_LIST = "Token in black list";

    public static final int EXPIRATION_TIME_MINUTES_IN_THE_FUTURE = 5;
    public static final int NOT_BEFORE_MINUTES_IN_THE_PAST = 2;
    public static final int SECONDS_OF_ALLOWED_CLOCK_SKEW = 30;

    public static final int RSA_KEY_SIZE = 2048;

    public static final String WHITE_SPACE = " ";
    public static final String ERROR_LOGIN = "LOGIN_ERROR";
    public static final String SERVER_ERROR = "Server error";
    public static final String INVALID_CREDENTIALS = "Invalid credentials";
    public static final String LOGIN_REQUIRED = "Login required probably because of expired jwt";
    public static final String BEARER = "Bearer";
    public static final String BEARER_AUTH = "Bearer %s";
    public static final String TOKEN_EXPIRED = "Token expired";
    public static final String TRUE = "true";
    public static final String NEWSPAPERS_API = "NewspapersAPI";
    public static final String CLIENTS = "Clients";
    public static final String API_AUTH = "API Auth";
    public static final String NOMBRE = "Nombre";
    public static final String ROLES = "Roles";
    public static final String KEY_ID = "VaultsAPI";
}
