package org.jorgetargz.server.dao.utils;

public class SQLQueries {

    public static final String INSERT_LOGIN_QUERY = "INSERT INTO login (username, role, certificate) VALUES (?, ?, ?)";
    public static final String SELECT_LOGIN_BY_USERNAME_QUERY = "SELECT * FROM login WHERE username = ?";
    public static final String DELETE_LOGIN_QUERY = "DELETE FROM login WHERE username = ?";

    public static final String GET_VAULTS = "select * from vaults where username = ?";
    public static final String SELECT_VAULT_BY_ID = "SELECT * FROM vaults WHERE id = ?";
    public static final String SELECT_VAULT_BY_NAME = "SELECT * FROM vaults WHERE name = ? AND username = ?";
    public static final String INSERT_VAULT_QUERY = "INSERT INTO vaults (name, username, `key`, `read`, `write`) VALUES (?, ?, ?, ?, ?)";
    public static final String DELETE_VAULT_QUERY = "DELETE FROM vaults WHERE id = ?";
    public static final String DELETE_VAULTS_QUERY_BY_USERNAME = "DELETE FROM vaults WHERE username = ?";

    public static final String SELECT_MESSAGES_QUERY = "SELECT * FROM messages WHERE vaultId = ?";
    public static final String INSERT_MESSAGE_QUERY = "INSERT INTO messages (vaultId, iv, salt, cipherText, signedBy, signature) VALUES (?, ?, ?, ?, ?, ?)";
    public static final String UPDATE_MESSAGE_QUERY = "UPDATE messages SET iv = ?, salt = ?, cipherText = ?, signedBy = ?, signature = ? WHERE id = ?";
    public static final String DELETE_MESSAGE_QUERY = "DELETE FROM messages WHERE id = ?";
    public static final String SELECT_VAULT_BY_MESSAGE_ID = "SELECT * FROM vaults WHERE id IN (SELECT vaultId FROM messages WHERE id = ?)";
    public static final String DELETE_MESSAGES_QUERY = "DELETE FROM messages WHERE vaultId = ?";
    public static final String DELETE_MESSAGES_QUERY_BY_USERNAME = "DELETE FROM messages WHERE vaultId IN (SELECT id FROM vaults WHERE username = ?)";

    public static final String INSERT_VAULT_SHARE = "INSERT INTO vaultShares (vaultId, username, `key`) VALUES (?,?,?)";
    public static final String SELECT_VAULT_KEY_FOR_USER = "SELECT `key` FROM vaultShares WHERE vaultId = ? AND username = ?";
    public static final String DELETE_VAULT_SHARES_QUERY_BY_VAULT_ID = "DELETE FROM vaultShares WHERE vaultId = ?";
    public static final String DELETE_VAULTS_SHARES_QUERY_BY_USERNAME = "DELETE FROM vaultShares WHERE username = ?";

    private SQLQueries() {
    }

}