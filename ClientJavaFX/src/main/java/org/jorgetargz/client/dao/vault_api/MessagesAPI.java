package org.jorgetargz.client.dao.vault_api;

import io.reactivex.rxjava3.core.Single;
import org.jorgetargz.utils.common.ConstantesAPI;
import org.jorgetargz.utils.modelo.Message;
import retrofit2.Response;
import retrofit2.http.*;

import java.util.List;

public interface MessagesAPI {

    @GET(ConstantesAPI.ENDPOINT_MESSAGES)
    Single<List<Message>> getMessages(
            @Query(ConstantesAPI.VAULT_NAME) String vaultName,
            @Query(ConstantesAPI.USERNAME_OWNER) String usernameOwner
    );

    @POST(ConstantesAPI.ENDPOINT_MESSAGES)
    Single<Message> create(@Body Message message);

    @PUT(ConstantesAPI.ENDPOINT_MESSAGES)
    Single<Message> update(@Body Message message);

    @DELETE(ConstantesAPI.ENDPOINT_MESSAGE_DELETE)
    Single<Response<Void>> delete(@Path(ConstantesAPI.MESSAGE_ID_PARAM) int messageId);

}
