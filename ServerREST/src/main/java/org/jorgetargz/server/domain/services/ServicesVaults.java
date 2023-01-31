package org.jorgetargz.server.domain.services;

import org.jorgetargz.utils.modelo.*;

import java.util.List;

public interface ServicesVaults {

    List<Vault> getVaults(String username);

    Vault getVault(Vault credentials, String usernameReader);

    Vault createVault(Vault vault);

    void changePassword(Vault credentials, String password, String usernameReader);

    void deleteVault(int vaultId, String usernameReader);
}
