package org.jorgetargz.server.domain.services.impl;

import jakarta.inject.Inject;
import jakarta.security.enterprise.identitystore.Pbkdf2PasswordHash;
import org.jorgetargz.server.dao.MessagesDao;
import org.jorgetargz.server.dao.VaultsDao;
import org.jorgetargz.server.domain.common.Constantes;
import org.jorgetargz.server.domain.services.ServicesMessages;
import org.jorgetargz.server.domain.services.excepciones.ValidationException;
import org.jorgetargz.utils.modelo.Message;
import org.jorgetargz.utils.modelo.Vault;

import java.util.Base64;
import java.util.List;

public class ServicesMessagesImpl implements ServicesMessages {

    private final MessagesDao messageDao;
    private final VaultsDao vaultsDao;
    private final Pbkdf2PasswordHash passwordHash;
    private final Base64.Decoder decoder;

    @Inject
    public ServicesMessagesImpl(MessagesDao messageDao, VaultsDao vaultsDao, Pbkdf2PasswordHash passwordHash) {
        this.messageDao = messageDao;
        this.vaultsDao = vaultsDao;
        this.passwordHash = passwordHash;
        this.decoder = Base64.getDecoder();
    }

    @Override
    public List<Message> getMessages(Vault credentials, String usernameReader) {
        String password = new String(decoder.decode(credentials.getPassword()));
        String username = new String(decoder.decode(credentials.getUsernameOwner()));
        String name = new String(decoder.decode(credentials.getName()));
        Vault vault = vaultsDao.getVault(username, name);
        if (passwordHash.verify(password.toCharArray(), vault.getPassword())) {
            if (vault.getUsernameOwner().equals(usernameReader) || vault.isReadByAll()) {
                return messageDao.getMessages(vault.getId());
            } else {
                throw new ValidationException(Constantes.YOU_DON_T_HAVE_PERMISSION_TO_READ_THIS_VAULT);
            }
        } else {
            throw new ValidationException(Constantes.WRONG_CREDENTIALS);
        }
    }

    @Override
    public Message createMessage(Message message, String password, String usernameReader) {
        int vaultId = message.getIdVault();
        Vault vault = vaultsDao.getVault(vaultId);
        password = new String(decoder.decode(password));
        checkPermsionToWrite(vault, password, usernameReader);
        return messageDao.createMessage(vaultId, message);
    }

    @Override
    public Message updateMessage(Message message, String password, String usernameReader) {
        password = new String(decoder.decode(password));
        checkPermsionToWrite(vaultsDao.getVault(message.getIdVault()), password, usernameReader);
        return messageDao.updateMessage(message);
    }

    private void checkPermsionToWrite(Vault vault, String password, String usernameReader) {
        if (passwordHash.verify(password.toCharArray(), vault.getPassword())) {
            if (!vault.getUsernameOwner().equals(usernameReader) && !vault.isWriteByAll()) {
                throw new ValidationException(Constantes.ONLY_THE_OWNER_OF_THE_VAULT_CAN_WRITE_IN_IT);
            }
        } else {
            throw new ValidationException(Constantes.WRONG_CREDENTIALS);
        }
    }

    @Override
    public void deleteMessage(int messageId, String usernameReader) {
        Vault vault = messageDao.getVault(messageId);
        if (vault.getUsernameOwner().equals(usernameReader)) {
            messageDao.deleteMessage(messageId);
        } else {
            throw new ValidationException(Constantes.ONLY_THE_OWNER_OF_THE_VAULT_CAN_DELETE_MESSAGES);
        }
    }
}
