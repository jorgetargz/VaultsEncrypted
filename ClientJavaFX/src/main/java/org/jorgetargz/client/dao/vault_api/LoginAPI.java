package org.jorgetargz.client.dao.vault_api;

import io.reactivex.rxjava3.core.Single;
import org.jorgetargz.client.dao.common.Constantes;
import org.jorgetargz.utils.common.ConstantesAPI;
import org.jorgetargz.utils.modelo.User;
import retrofit2.Response;
import retrofit2.http.GET;
import retrofit2.http.Header;

public interface LoginAPI {

    @GET(ConstantesAPI.ENDPOINT_LOGIN)
    Single<User> getReaderByLogin(@Header(Constantes.AUTHORIZATION) String authorization);

    @GET(ConstantesAPI.ENDPOINT_LOGOUT)
    Single<Response<Void>> logout(@Header(Constantes.AUTHORIZATION) String authorization);

}
