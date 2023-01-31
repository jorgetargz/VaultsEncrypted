package org.jorgetargz.client.dao.impl;

import com.google.gson.Gson;
import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import jakarta.inject.Inject;
import org.jorgetargz.client.dao.MessagesDAO;
import org.jorgetargz.client.dao.vault_api.MessagesAPI;
import org.jorgetargz.utils.modelo.Message;

import java.util.List;

public class MessagesDAOImpl extends GenericDAO implements MessagesDAO {

    private final MessagesAPI messagesAPI;

    @Inject
    public MessagesDAOImpl(Gson gson, MessagesAPI messagesAPI) {
        super(gson);
        this.messagesAPI = messagesAPI;
    }

    @Override
    public Single<Either<String, List<Message>>> getAll(String vaultName, String username, String password) {
        return safeAPICall(messagesAPI.getMessages(vaultName, username, password));
    }

    @Override
    public Single<Either<String, Message>> save(Message message, String password) {
        return safeAPICall(messagesAPI.create(message, password));
    }

    @Override
    public Single<Either<String, Message>> update(Message message, String password) {
        return safeAPICall(messagesAPI.update(message, password));
    }

    @Override
    public Single<Either<String, Boolean>> delete(int messageId) {
        return safeAPICallResponseVoid(messagesAPI.delete(messageId));
    }
}
