package org.jorgetargz.server.dao.jdbc_impl;

import jakarta.inject.Inject;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.server.dao.DBConnection;
import org.jorgetargz.server.dao.VaultsDao;
import org.jorgetargz.server.dao.common.Constantes;
import org.jorgetargz.server.dao.excepciones.DatabaseException;
import org.jorgetargz.server.dao.excepciones.NotFoundException;
import org.jorgetargz.server.dao.utils.SQLQueries;
import org.jorgetargz.utils.modelo.Vault;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@Log4j2
public class VaultsDaoImpl implements VaultsDao {

    private final DBConnection dbConnection;

    @Inject
    public VaultsDaoImpl(DBConnection dbConnection) {
        this.dbConnection = dbConnection;
    }

    @Override
    public List<Vault> getVaults(String username) {
        List<Vault> vaults = new ArrayList<>();
        try (Connection connection = dbConnection.getConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.GET_VAULTS)) {
            preparedStatement.setString(1, username);
            ResultSet resultSet = preparedStatement.executeQuery();
            while (resultSet.next()) {
                vaults.add(getVault(resultSet));
            }
            if (vaults.isEmpty()) {
                throw new NotFoundException(Constantes.VAULT_NOT_FOUND);
            }
        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(e.getMessage());
        }
        return vaults;
    }

    @Override
    public Vault getVault(int vaultId) {
        try (Connection connection = dbConnection.getConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.SELECT_VAULT_BY_ID)) {
            preparedStatement.setInt(1, vaultId);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                return getVault(resultSet);
            } else {
                throw new NotFoundException(Constantes.VAULT_NOT_FOUND);
            }

        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }

    @Override
    public Vault getVault(String username, String name) {
        try (Connection connection = dbConnection.getConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.SELECT_VAULT_BY_NAME)) {
            preparedStatement.setString(1, name);
            preparedStatement.setString(2, username);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                return getVault(resultSet);
            } else {
                throw new NotFoundException(Constantes.VAULT_NOT_FOUND);
            }
        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }

    private Vault getVault(ResultSet resultSet) throws SQLException {
        return Vault.builder()
                .id(resultSet.getInt(Constantes.ID))
                .name(resultSet.getString(Constantes.NAME))
                .usernameOwner(resultSet.getString(Constantes.USERNAME))
                .key(resultSet.getString(Constantes.KEY))
                .readByAll(resultSet.getBoolean(Constantes.READ_BY_ALL))
                .writeByAll(resultSet.getBoolean(Constantes.WRITE_BY_ALL))
                .build();
    }

    @Override
    public Vault createVault(Vault vault) {
        try (Connection connection = dbConnection.getConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.INSERT_VAULT_QUERY, Statement.RETURN_GENERATED_KEYS)) {
            preparedStatement.setString(1, vault.getName());
            preparedStatement.setString(2, vault.getUsernameOwner());
            preparedStatement.setString(3, vault.getKey());
            preparedStatement.setInt(4, vault.isReadByAll() ? 1 : 0);
            preparedStatement.setInt(5, vault.isWriteByAll() ? 1 : 0);
            preparedStatement.executeUpdate();
            ResultSet resultSet = preparedStatement.getGeneratedKeys();
            if (resultSet.next()) {
                vault.setId(resultSet.getInt(1));
                return vault;
            } else {
                throw new DatabaseException(Constantes.DATABASE_ERROR);
            }
        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }

    @Override
    public void changePassword(int vaultId, String newPassword) {
        try (Connection connection = dbConnection.getConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.UPDATE_VAULT_KEY_QUERY)) {
            preparedStatement.setString(1, newPassword);
            preparedStatement.setInt(2, vaultId);
            if (preparedStatement.executeUpdate() != 1) {
                throw new NotFoundException(Constantes.VAULT_NOT_FOUND);
            }
        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }

    @Override
    public void deleteVault(int vaultId) {
        try (Connection connection = dbConnection.getConnection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.DELETE_MESSAGES_QUERY)) {
                preparedStatement.setInt(1, vaultId);
                preparedStatement.executeUpdate();
            }
            try (PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.DELETE_VAULT_QUERY)) {
                preparedStatement.setInt(1, vaultId);
                if (preparedStatement.executeUpdate() == 1) {
                    connection.commit();
                } else {
                    throw new NotFoundException(Constantes.VAULT_NOT_FOUND);
                }
            }
        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }
}