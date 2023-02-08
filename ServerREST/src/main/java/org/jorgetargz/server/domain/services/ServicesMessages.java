package org.jorgetargz.server.domain.services;

import org.jorgetargz.utils.modelo.Message;
import org.jorgetargz.utils.modelo.Vault;

import java.util.List;

public interface ServicesMessages {

    List<Message> getMessages(Vault credential, String usernameReader);

    Message createMessage(Message message, String usernameReader);

    Message updateMessage(Message message, String usernameReader);

    void deleteMessage(int messageId, String usernameReader);
}
