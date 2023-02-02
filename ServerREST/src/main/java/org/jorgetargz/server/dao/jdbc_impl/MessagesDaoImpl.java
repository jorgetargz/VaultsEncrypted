package org.jorgetargz.server.dao.jdbc_impl;

import jakarta.inject.Inject;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.server.dao.DBConnection;
import org.jorgetargz.server.dao.MessagesDao;
import org.jorgetargz.server.dao.common.Constantes;
import org.jorgetargz.server.dao.excepciones.DatabaseException;
import org.jorgetargz.server.dao.excepciones.NotFoundException;
import org.jorgetargz.server.dao.utils.SQLQueries;
import org.jorgetargz.utils.modelo.ContentCiphedAES;
import org.jorgetargz.utils.modelo.Message;
import org.jorgetargz.utils.modelo.Vault;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@Log4j2
public class MessagesDaoImpl implements MessagesDao {

    private final DBConnection dbConnection;

    @Inject
    public MessagesDaoImpl(DBConnection dbConnection) {
        this.dbConnection = dbConnection;
    }

    @Override
    public Vault getVault(int messageId) {
        try (Connection connection = dbConnection.getConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.SELECT_VAULT_BY_MESSAGE_ID)) {
            preparedStatement.setInt(1, messageId);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                return Vault.builder()
                        .id(resultSet.getInt(Constantes.ID))
                        .name(resultSet.getString(Constantes.NAME))
                        .usernameOwner(resultSet.getString(Constantes.USERNAME))
                        .key(resultSet.getString(Constantes.KEY))
                        .readByAll(resultSet.getBoolean(Constantes.READ_BY_ALL))
                        .writeByAll(resultSet.getBoolean(Constantes.WRITE_BY_ALL))
                        .build();
            } else {
                throw new NotFoundException(Constantes.VAULT_NOT_FOUND);
            }
        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }

    @Override
    public List<Message> getMessages(int vaultId) {
        try (Connection connection = dbConnection.getConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.SELECT_MESSAGES_QUERY)) {
            preparedStatement.setInt(1, vaultId);
            ResultSet resultSet = preparedStatement.executeQuery();
            List<Message> messages = new ArrayList<>();
            while (resultSet.next()) {
                Message message = Message.builder()
                        .id(resultSet.getInt(Constantes.ID))
                        .idVault(vaultId)
                        .contentCiphedAES(ContentCiphedAES.builder()
                                .iv(resultSet.getString(Constantes.IV))
                                .salt(resultSet.getString(Constantes.SALT))
                                .cipherText(resultSet.getString(Constantes.CIPHER_TEXT))
                                .build())
                        .build();
                messages.add(message);
            }
            return messages;
        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }

    @Override
    public Message createMessage(int vaultId, Message message) {
        try (Connection connection = dbConnection.getConnection();
             PreparedStatement preparedStatementInsertMessage = connection.prepareStatement(SQLQueries.INSERT_MESSAGE_QUERY, Statement.RETURN_GENERATED_KEYS)) {

            preparedStatementInsertMessage.setInt(1, vaultId);
            preparedStatementInsertMessage.setString(2, message.getContentCiphedAES().getIv());
            preparedStatementInsertMessage.setString(3, message.getContentCiphedAES().getSalt());
            preparedStatementInsertMessage.setString(4, message.getContentCiphedAES().getCipherText());
            preparedStatementInsertMessage.executeUpdate();
            ResultSet resultSetMessage = preparedStatementInsertMessage.getGeneratedKeys();
            if (resultSetMessage.next()) {
                return Message.builder()
                        .id(resultSetMessage.getInt(1))
                        .idVault(vaultId)
                        .contentCiphedAES(message.getContentCiphedAES())
                        .build();
            } else {
                throw new DatabaseException(Constantes.DATABASE_ERROR);
            }

        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }

    @Override
    public Message updateMessage(Message message) {
        try (Connection connection = dbConnection.getConnection();
             PreparedStatement preparedStatementUpdateMessage = connection.prepareStatement(SQLQueries.UPDATE_MESSAGE_QUERY)) {

            preparedStatementUpdateMessage.setString(1, message.getContentCiphedAES().getIv());
            preparedStatementUpdateMessage.setString(2, message.getContentCiphedAES().getSalt());
            preparedStatementUpdateMessage.setString(3, message.getContentCiphedAES().getCipherText());
            preparedStatementUpdateMessage.setInt(4, message.getId());
            if (preparedStatementUpdateMessage.executeUpdate() == 1) {
                return Message.builder()
                        .id(message.getId())
                        .contentCiphedAES(message.getContentCiphedAES())
                        .build();
            } else {
                throw new NotFoundException(Constantes.MESSAGE_NOT_FOUND);
            }
        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }

    @Override
    public void deleteMessage(int messageId) {
        try (Connection connection = dbConnection.getConnection();
             PreparedStatement preparedStatementDeleteMessage = connection.prepareStatement(SQLQueries.DELETE_MESSAGE_QUERY)) {

            preparedStatementDeleteMessage.setInt(1, messageId);
            if (preparedStatementDeleteMessage.executeUpdate() != 1) {
                throw new NotFoundException(Constantes.MESSAGE_NOT_FOUND);
            }
        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }

}
