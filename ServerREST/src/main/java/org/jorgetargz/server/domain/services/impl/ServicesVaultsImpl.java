package org.jorgetargz.server.domain.services.impl;

import jakarta.inject.Inject;
import jakarta.security.enterprise.identitystore.Pbkdf2PasswordHash;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.security.EncriptacionAES;
import org.jorgetargz.server.dao.MessagesDao;
import org.jorgetargz.server.dao.VaultsDao;
import org.jorgetargz.server.domain.common.Constantes;
import org.jorgetargz.server.domain.services.ServicesVaults;
import org.jorgetargz.server.domain.services.excepciones.ValidationException;
import org.jorgetargz.utils.modelo.ContentCiphedAES;
import org.jorgetargz.utils.modelo.Message;
import org.jorgetargz.utils.modelo.Vault;

import java.util.Base64;
import java.util.List;

@Log4j2
public class ServicesVaultsImpl implements ServicesVaults {

    private final VaultsDao vaultsDao;
    private final MessagesDao messageDao;
    private final Pbkdf2PasswordHash passwordHash;
    private final EncriptacionAES encriptacionAES;
    private final Base64.Decoder decoder;

    @Inject
    public ServicesVaultsImpl(VaultsDao vaultsDao, MessagesDao messageDao, Pbkdf2PasswordHash passwordHash, EncriptacionAES encriptacionAES) {
        this.vaultsDao = vaultsDao;
        this.messageDao = messageDao;
        this.passwordHash = passwordHash;
        this.encriptacionAES = encriptacionAES;
        this.decoder = Base64.getUrlDecoder();
    }

    @Override
    public List<Vault> getVaults(String usernameLogged) {
        return vaultsDao.getVaults(usernameLogged);
    }

    @Override
    public Vault createVault(Vault vault) {
        return vaultsDao.createVault(vault);
    }

    @Override
    public Vault shareVault(Vault vaultInfo, String usernameToShare, String passwordEncWithUserPubKey, String usernameLogged) {
        Vault vault = vaultsDao.getVault(vaultInfo.getUsernameOwner(), vaultInfo.getName());
        if (vault.getUsernameOwner().equals(usernameLogged)) {
            usernameToShare = new String(decoder.decode(usernameToShare));
            return vaultsDao.shareVault(vault, usernameToShare, passwordEncWithUserPubKey);
        } else {
            throw new ValidationException("Only owner can share the vault");
        }
    }

    @Override
    public Vault getVault(Vault vaultInfo, String usernameLogged) {
        String username = new String(decoder.decode(vaultInfo.getUsernameOwner()));
        String name = new String(decoder.decode(vaultInfo.getName()));
        Vault vault = vaultsDao.getVault(username, name);
        boolean isOwner = vault.getUsernameOwner().equals(usernameLogged);
        if (isOwner || vault.isReadByAll()) {
            if (isOwner) return vault;
            else {
                String vaultKey = vaultsDao.getVaultKeyForUser(vault.getId(), usernameLogged);
                vault.setKey(vaultKey);
                return vault;
            }
        } else {
            throw new ValidationException(Constantes.ONLY_THE_OWNER_CAN_READ_THIS_VAULT);
        }
    }

    @Override
    public void changePassword(Vault vaultInfo, String password, String usernameLogged) {
        String newPassword = new String(decoder.decode(password));
        int vaultId = vaultInfo.getId();
        Vault vault = vaultsDao.getVault(vaultId);
        if (passwordHash.verify(vaultInfo.getKey().toCharArray(), vault.getKey())
                && vault.getUsernameOwner().equals(usernameLogged)) {

            List<Message> messages = messageDao.getMessages(vaultId);
            for (Message message : messages) {
                String messageText = encriptacionAES.desencriptar(message.getContentCiphedAES(), vaultInfo.getKey());
                ContentCiphedAES contentCiphedAES = encriptacionAES.encriptar(messageText, newPassword);
                message.setContentCiphedAES(contentCiphedAES);
                messageDao.updateMessage(message);
            }

            String newPasswordHashed = passwordHash.generate(newPassword.toCharArray());
            vaultsDao.changePassword(vaultId, newPasswordHashed);
        } else {
            throw new ValidationException(Constantes.NOT_THE_OWNER_OF_THIS_VAULT_OR_THE_PASSWORD_IS_INCORRECT);
        }
    }

    @Override
    public void deleteVault(int vaultId, String usernameLogged) {
        Vault vault = vaultsDao.getVault(vaultId);
        if (vault.getUsernameOwner().equals(usernameLogged)) {
            vaultsDao.deleteVault(vaultId);
        } else {
            throw new ValidationException(Constantes.ONLY_THE_OWNER_OF_THE_VAULT_CAN_DELETE_IT);
        }
    }
}