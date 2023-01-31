package org.jorgetargz.server.dao.jdbc_impl;

import org.jorgetargz.server.dao.DBConnection;
import org.jorgetargz.server.dao.UsersDao;
import org.jorgetargz.server.dao.common.Constantes;
import org.jorgetargz.server.dao.excepciones.DatabaseException;
import org.jorgetargz.server.dao.excepciones.NotFoundException;
import org.jorgetargz.server.dao.utils.SQLQueries;
import jakarta.inject.Inject;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.utils.modelo.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@Log4j2
public class UsersDaoImpl implements UsersDao {

    private final DBConnection dbConnection;

    @Inject
    public UsersDaoImpl(DBConnection dbConnection) {
        this.dbConnection = dbConnection;
    }

    public User get(String username) {
        try (Connection connection = dbConnection.getConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.SELECT_LOGIN_BY_USERNAME_QUERY)) {
            preparedStatement.setString(1, username);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                return getLoginFromResultSet(resultSet);
            } else {
                log.warn(Constantes.LOGIN_NOT_FOUND);
                throw new NotFoundException(Constantes.LOGIN_NOT_FOUND);
            }
        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }

    @Override
    public User save(User user) {
        try (Connection connection = dbConnection.getConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.INSERT_LOGIN_QUERY)) {
            preparedStatement.setString(1, user.getUsername());
            preparedStatement.setString(2, user.getRole());
            preparedStatement.setString(3, user.getCertificate());
            preparedStatement.executeUpdate();
            return user;
        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }

    @Override
    public void delete(String username) {
        try (Connection connection = dbConnection.getConnection()) {
             connection.setAutoCommit(false);
             // Delete all messages from the user
             try (PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.DELETE_MESSAGES_QUERY_BY_USERNAME)){
                 preparedStatement.setString(1, username);
                 preparedStatement.executeUpdate();
             }
             // Delete all vaults from the user
             try (PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.DELETE_VAULTS_QUERY_BY_USERNAME)){
                 preparedStatement.setString(1, username);
                 preparedStatement.executeUpdate();
             }
             // Delete the user
             try (PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.DELETE_LOGIN_QUERY)){
                 preparedStatement.setString(1, username);
                 preparedStatement.executeUpdate();
             }
             // Commit the transaction
             connection.commit();
        } catch (SQLException e) {
            log.error(e.getMessage());
            throw new DatabaseException(Constantes.DATABASE_ERROR);
        }
    }

    private User getLoginFromResultSet(ResultSet resultSet) throws SQLException {
        return User.builder()
                .username(resultSet.getString(Constantes.USERNAME))
                .role(resultSet.getString(Constantes.ROLE))
                .certificate(resultSet.getString(Constantes.CERTIFICATE))
                .build();
    }

}