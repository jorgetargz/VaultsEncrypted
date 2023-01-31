package org.jorgetargz.server.dao;

import org.jorgetargz.utils.modelo.Message;
import org.jorgetargz.utils.modelo.Vault;

import java.util.List;

public interface MessagesDao {

    Vault getVault(int messageId);

    List<Message> getMessages(int vaultId);

    Message createMessage(int vaultId, Message message);

    Message updateMessage(Message message);

    void deleteMessage(int messageId);
}
