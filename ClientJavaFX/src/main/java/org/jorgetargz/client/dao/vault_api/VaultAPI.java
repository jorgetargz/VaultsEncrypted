package org.jorgetargz.client.dao.vault_api;

import io.reactivex.rxjava3.core.Single;
import org.jorgetargz.utils.common.ConstantesAPI;
import org.jorgetargz.utils.modelo.Vault;
import retrofit2.Response;
import retrofit2.http.*;

import java.util.List;

public interface VaultAPI {

    @GET(ConstantesAPI.ENDPOINT_VAULT)
    Single<List<Vault>> getVaults();

    @GET(ConstantesAPI.ENDPOINT_VAULT_GET)
    Single<Vault> getVault(@Query(ConstantesAPI.VAULT_NAME) String vaultName,
                           @Query(ConstantesAPI.USERNAME_OWNER) String usernameOwner,
                           @Query(ConstantesAPI.PASSWORD) String password);

    @POST(ConstantesAPI.ENDPOINT_VAULT)
    Single<Vault> createVault(@Body Vault vault);

    @POST(ConstantesAPI.ENDPOINT_VAULT_CHANGE_PASSWORD)
    Single<Response<Void>> changePassword(@Body Vault credentials, @Query(ConstantesAPI.PASSWORD) String password);

    @DELETE(ConstantesAPI.ENDPOINT_VAULT_DELETE)
    Single<Response<Void>> deleteVault(@Path(ConstantesAPI.VAULT_ID_PARAM) int vaultId);
}
