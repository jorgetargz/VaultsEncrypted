package org.jorgetargz.client.domain.common;

public class Constantes {

    public static final String RSA = "RSA";
    public static final int KEY_SIZE = 2048;
    public static final int PASS_FOR_ENC_PUB_KEY_SIZE = 16;
    public static final int STRING_FOR_LOGIN_SIGNATURE_PROCESS_SIZE = 20;

    public static final String SERVER_PUBLIC_KEY = "serverPublicKey";
    public static final String KEY_STORE_PFX = "KeyStore.pfx";

    public static final String CERTIFICATE = "Certificate ";
    public static final String SEPARATOR = ":";

    public static final String PRIVADA_ALIAS = "privada";
    public static final String PUBLICA_ALIAS = "publica";

    public static final String NO_EXISTE_EL_KEYSTORE = "No existe el keystore";
    public static final String ERROR_AL_LEER_EL_KEY_STORE = "Error al leer el KeyStore";
    public static final String ERROR_AL_OBTENER_LA_CLAVE_PRIVADA_DEL_KEY_STORE = "Error al obtener la clave privada del KeyStore";
    public static final String ERROR_AL_FIRMAR_EL_STRING_ALEATORIO = "Error al firmar el String aleatorio";
    public static final String ERROR_AL_GENERAR_LAS_CLAVES_RSA = "Error al generar las claves RSA";
    public static final String ERROR_AL_ENCRIPTAR_LA_CLAVE_ALEATORIA = "Error al encriptar la clave aleatoria";
    public static final String ERROR_AL_GUARDAR_EL_USUARIO_EN_LA_BASE_DE_DATOS = "Error al guardar el usuario en la base de datos";
    public static final String ERROR_AL_CREAR_EL_KEY_STORE = "Error al crear el KeyStore";
    public static final String ERROR_AL_GUARDAR_EL_KEY_STORE = "Error al guardar el KeyStore";
    public static final String ERROR_READING_KEYSTORE = "Error reading keystore";
    public static final String ERROR_READING_PRIVATE_KEY = "Error reading private key";
    public static final String ERROR_DECRYPTING_PASSWORD = "Error decrypting password";
    public static final String WRONG_PASSWORD = "Wrong password";
    public static final String ERROR_AL_OBTENER_LA_CLAVE_PUB_DEL_CERT = "Error al obtener la clave pública del certificado";
    public static final String ERROR_AL_CIFRAR_LA_CLAVE_DEL_VAULT = "Error al cifrar la contraseña del vault";
    public static final String ERROR_GETTING_USER = "Error getting user";
    public static final String ERROR_AL_ENCRIPTAR_LA_CLAVE_DEL_VAULT_CON_LA_CLAVE_PUBLICA_DEL_USUARIO_A_COMPARTIR = "Error al encriptar la clave del vault con la clave publica del usuario a compartir";
    public static final String ERROR_AL_OBTENER_LA_CLAVE_PUB_DEL_SERVIDOR = "Error al obtener la clave pública del servidor";
    public static final String COULDN_T_VERIFY = "Couldn't verify";

    private Constantes() {
    }


}
