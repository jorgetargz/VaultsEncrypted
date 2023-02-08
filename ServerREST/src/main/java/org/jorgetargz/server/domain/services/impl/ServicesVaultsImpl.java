package org.jorgetargz.server.domain.services.impl;

import jakarta.inject.Inject;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.server.dao.VaultsDao;
import org.jorgetargz.server.domain.common.Constantes;
import org.jorgetargz.server.domain.services.ServicesVaults;
import org.jorgetargz.server.domain.services.excepciones.ValidationException;
import org.jorgetargz.utils.modelo.Vault;

import java.util.Base64;
import java.util.List;

@Log4j2
public class ServicesVaultsImpl implements ServicesVaults {

    private final VaultsDao vaultsDao;
    private final Base64.Decoder decoder;

    @Inject
    public ServicesVaultsImpl(VaultsDao vaultsDao) {
        this.vaultsDao = vaultsDao;
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
            if (!vault.isReadByAll()) {
                throw new ValidationException(Constantes.THIS_VAULT_CAN_T_BE_SHARED_BECAUSE_IT_S_PRIVATE);
            }
            usernameToShare = new String(decoder.decode(usernameToShare));
            return vaultsDao.shareVault(vault, usernameToShare, passwordEncWithUserPubKey);
        } else {
            throw new ValidationException(Constantes.ONLY_OWNER_CAN_SHARE_THE_VAULT);
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
    public void deleteVault(int vaultId, String usernameLogged) {
        Vault vault = vaultsDao.getVault(vaultId);
        if (vault.getUsernameOwner().equals(usernameLogged)) {
            vaultsDao.deleteVault(vaultId);
        } else {
            throw new ValidationException(Constantes.ONLY_THE_OWNER_OF_THE_VAULT_CAN_DELETE_IT);
        }
    }
}