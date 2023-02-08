package org.jorgetargz.server.domain.services;

import org.jorgetargz.utils.modelo.*;

import java.util.List;

public interface ServicesVaults {

    List<Vault> getVaults(String usernameLogged);

    Vault getVault(Vault vaultInfo, String usernameLogged);

    Vault createVault(Vault vault);

    Vault shareVault(Vault vaultInfo, String usernameToShare, String passwordEncWithUserPubKey, String usernameLogged);

    void deleteVault(int vaultId, String usernameLogged);
}
