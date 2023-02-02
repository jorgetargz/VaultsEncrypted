package org.jorgetargz.client.dao.vault_api;

import io.reactivex.rxjava3.core.Single;
import org.jorgetargz.utils.common.ConstantesAPI;
import retrofit2.http.GET;

public interface SecurityAPI {

    @GET(ConstantesAPI.ENDPOINT_PUBLIC_KEY)
    Single<String> getPublicKey();
}
