package org.jorgetargz.server.domain.services.impl;

import jakarta.inject.Inject;
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
    private final Base64.Decoder decoder;

    @Inject
    public ServicesMessagesImpl(MessagesDao messageDao, VaultsDao vaultsDao) {
        this.messageDao = messageDao;
        this.vaultsDao = vaultsDao;
        this.decoder = Base64.getUrlDecoder();
    }

    @Override
    public List<Message> getMessages(Vault vaultInfo, String usernameReader) {
        String username = new String(decoder.decode(vaultInfo.getUsernameOwner()));
        String name = new String(decoder.decode(vaultInfo.getName()));
        Vault vault = vaultsDao.getVault(username, name);
        if (vault.getUsernameOwner().equals(usernameReader) || vault.isReadByAll()) {
            return messageDao.getMessages(vault.getId());
        } else {
            throw new ValidationException(Constantes.YOU_DON_T_HAVE_PERMISSION_TO_READ_THIS_VAULT);
        }
    }

    @Override
    public Message createMessage(Message message, String usernameReader) {
        int vaultId = message.getIdVault();
        Vault vault = vaultsDao.getVault(vaultId);
        checkPermsionToWrite(vault, usernameReader);
        return messageDao.createMessage(vaultId, message);
    }

    @Override
    public Message updateMessage(Message message, String usernameReader) {
        checkPermsionToWrite(vaultsDao.getVault(message.getIdVault()), usernameReader);
        return messageDao.updateMessage(message);
    }

    private void checkPermsionToWrite(Vault vault, String usernameReader) {
            if (!vault.getUsernameOwner().equals(usernameReader) && !vault.isWriteByAll()) {
                throw new ValidationException(Constantes.ONLY_THE_OWNER_OF_THE_VAULT_CAN_WRITE_IN_IT);
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
