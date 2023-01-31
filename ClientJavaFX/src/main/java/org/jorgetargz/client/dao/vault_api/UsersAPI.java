package org.jorgetargz.client.dao.vault_api;

import io.reactivex.rxjava3.core.Single;
import org.jorgetargz.utils.common.ConstantesAPI;
import org.jorgetargz.utils.modelo.User;
import retrofit2.Response;
import retrofit2.http.Body;
import retrofit2.http.DELETE;
import retrofit2.http.POST;
import retrofit2.http.Path;

public interface UsersAPI {

    @POST(ConstantesAPI.ENDPOINT_USERS)
    Single<User> create(@Body User user);

    @DELETE(ConstantesAPI.ENDPOINT_USER_DELETE)
    Single<Response<Void>> delete(@Path(ConstantesAPI.USERNAME_PARAM) String username);

}
