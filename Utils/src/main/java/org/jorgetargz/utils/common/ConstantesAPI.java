package org.jorgetargz.utils.common;

public class ConstantesAPI {

    public static final String API_PATH = "api/";

    //Main Paths for REST /api
    public static final String PATH_LOGIN = "login/";
    public static final String PATH_USERS = "users/";
    public static final String PATH_VAULTS = "vaults/";
    public static final String PATH_MESSAGES = "messages/";
    public static final String PATH_SECURITY = "security/";

    //Auxiliar Paths for REST /api/mainPath/auxPath
    public static final String LOGOUT_PATH = "logout/";
    public static final String VAULT_PATH = "vault/";
    public static final String PUBLIC_KEY_PATH = "publicKey/";
    public static final String SHARE_PATH = "share/";

    //Path Parameters
    public static final String VAULT_ID_PATH_PARAM = "{vaultId}";
    public static final String VAULT_ID_PARAM = "vaultId";
    public static final String MESSAGE_ID_PATH_PARAM = "{messageId}";
    public static final String MESSAGE_ID_PARAM = "messageId";
    public static final String USERNAME_PATH_PARAM = "{username}";
    public static final String USERNAME_PARAM = "username";

    //Query Parameters
    public static final String VAULT_NAME = "vaultName";
    public static final String USERNAME_OWNER = "usernameOwner";
    public static final String PASS_ENC_WITH_USER_PUB_KEY_PARAM = "passEncWithUserPubKey";

    //ENDPOINTS LOGIN
    public static final String ENDPOINT_LOGIN = PATH_LOGIN;
    public static final String ENDPOINT_LOGOUT = PATH_LOGIN + LOGOUT_PATH;

    //ENDPOINTS VAULT
    public static final String ENDPOINT_VAULT = PATH_VAULTS;
    public static final String ENDPOINT_VAULT_GET = PATH_VAULTS + VAULT_PATH;
    public static final String ENDPOINT_VAULT_DELETE = PATH_VAULTS + VAULT_ID_PATH_PARAM;
    public static final String ENDPOINT_VAULT_SHARE = PATH_VAULTS + SHARE_PATH;

    //ENDPOINTS MESSAGES
    public static final String ENDPOINT_MESSAGES = PATH_MESSAGES;
    public static final String ENDPOINT_MESSAGE_DELETE = PATH_MESSAGES + MESSAGE_ID_PATH_PARAM;

    //ENDPOINTS USERS
    public static final String ENDPOINT_USERS = PATH_USERS;
    public static final String ENDPOINT_GET_USER = PATH_USERS + USERNAME_PATH_PARAM;
    public static final String ENDPOINT_USER_DELETE = PATH_USERS + USERNAME_PATH_PARAM;

    //ENDPOINTS SECURITY
    public static final String ENDPOINT_PUBLIC_KEY = PATH_SECURITY + PUBLIC_KEY_PATH;

    //Roles
    public static final String ROLE_ADMIN = "ADMIN";
    public static final String ROLE_USER = "USER";

    private ConstantesAPI() {
    }
}
