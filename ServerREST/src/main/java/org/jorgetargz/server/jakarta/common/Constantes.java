package org.jorgetargz.server.jakarta.common;

public class Constantes {

    public static final String PATH_SERVER_KEYSTORE = "/opt/payara/appserver/glassfish/domains/domain1/applications/ServerRest-1.0-SNAPSHOT/WEB-INF/classes/keys/keystore.pfx";
    public static final String SERVER_SECRET_KEY = "serverSecretKey";

    public static final String CERTIFICATE = "Certificate";
    public static final String SEPARATOR = ":";

    public static final String SHA_256_WITH_RSA = "SHA256WithRSA";
    public static final String PUBLICA = "publica";
    public static final String PRIVADA = "privada";
    public static final String SERVER = "SERVER";

    public static final int EXPIRATION_TIME_MINUTES_IN_THE_FUTURE = 5;
    public static final int NOT_BEFORE_MINUTES_IN_THE_PAST = 2;
    public static final int SECONDS_OF_ALLOWED_CLOCK_SKEW = 30;
    public static final int KEY_SIZE = 2048;

    public static final String WHITE_SPACE = " ";

    public static final String BEARER = "Bearer";
    public static final String BEARER_AUTH = "Bearer %s";
    public static final String TRUE = "true";
    public static final String NEWSPAPERS_API = "NewspapersAPI";
    public static final String CLIENTS = "Clients";
    public static final String API_AUTH = "API Auth";
    public static final String NOMBRE = "Nombre";
    public static final String ROLES = "Roles";

    public static final String ERROR_AL_CARGAR_EL_KEY_STORE = "Error al cargar el KeyStore";
    public static final String ERROR_AL_OBTENER_LA_CLAVE_PUBLICA_DEL_CERTIFICADO = "Error al obtener la clave publica del certificado";
    public static final String ERROR_AL_OBTENER_LA_CLAVE_PRIVADA_DEL_KEY_STORE = "Error al obtener la clave privada del KeyStore";
    public static final String ERROR_AL_CREAR_EL_KEY_STORE = "Error al crear el KeyStore";
    public static final String NO_SE_HA_PODIDO_GUARDAR_EL_KEY_STORE_EN_EL_FICHERO = "No se ha podido guardar el KeyStore en el fichero";
    public static final String ERROR_LOGIN = "LOGIN_ERROR";
    public static final String SERVER_ERROR = "Server error";
    public static final String INVALID_CREDENTIALS = "Invalid credentials";
    public static final String LOGIN_REQUIRED = "Login required probably because of expired jwt";
    public static final String TOKEN_EXPIRED = "Token expired";
    public static final String TOKEN_IN_BLACK_LIST = "Token in black list";

    private Constantes() {
    }
}
