package org.jorgetargz.client.dao.impl;

import com.google.gson.Gson;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.schedulers.Schedulers;
import io.vavr.control.Either;
import jakarta.inject.Inject;
import lombok.extern.log4j.Log4j2;
import okhttp3.MediaType;
import okhttp3.ResponseBody;
import org.jorgetargz.client.dao.common.Constantes;
import org.jorgetargz.utils.modelo.BaseError;
import retrofit2.HttpException;
import retrofit2.Response;

import java.io.IOException;
import java.util.Objects;

@Log4j2
public class GenericDAO {

    private final Gson gson;

    @Inject
    public GenericDAO(Gson gson) {
        this.gson = gson;
    }

    public <T> Single<Either<String, T>> safeAPICall(Single<T> apiCall) {
        return apiCall.map(t -> Either.right(t).mapLeft(Object::toString))
                .subscribeOn(Schedulers.io())
                .onErrorReturn(this::getError);
    }

    public Single<Either<String, Boolean>> safeAPICallResponseVoid(Single<Response<Void>> apiCall) {
        return apiCall.map(objectResponse -> {
                    if (objectResponse.isSuccessful()) {
                        return Either.right(true).mapLeft(Object::toString);
                    } else {
                        Either<String, Boolean> result;
                        ResponseBody responseBody = Objects.requireNonNull(objectResponse.errorBody());
                        if (Objects.equals(responseBody.contentType(), MediaType.get(Constantes.APPLICATION_JSON))) {
                            BaseError apierror = gson.fromJson(responseBody.string(), BaseError.class);
                            result = Either.left(apierror.getMessage());
                        } else {
                            result = Either.left(objectResponse.message());
                            if (objectResponse.code() == 401 || objectResponse.code() == 403) {
                                result = Either.left(Constantes.ERROR_DE_AUTENTICACION);
                            }
                        }
                        return result;
                    }
                })
                .subscribeOn(Schedulers.io())
                .onErrorReturn(this::getError);
    }


    private <T> Either<String, T> getError(Throwable throwable) {
        Either<String, T> error = Either.left(Constantes.ERROR_DE_COMUNICACION);
        if (throwable instanceof HttpException httpException) {
            try (ResponseBody responseBody = Objects.requireNonNull(httpException.response()).errorBody()) {
                if (Objects.equals(Objects.requireNonNull(responseBody).contentType(),
                        MediaType.get(Constantes.APPLICATION_JSON))) {
                    BaseError apierror = gson.fromJson(responseBody.string(), BaseError.class);
                    error = Either.left(apierror.getMessage());
                } else {
                    error = Either.left(Objects.requireNonNull(httpException.response()).message());
                    if (Objects.requireNonNull(httpException.response()).code() == 401 || Objects.requireNonNull(httpException.response()).code() == 403) {
                        error = Either.left(Constantes.ERROR_DE_AUTENTICACION);
                    }
                }
            } catch (IOException e) {
                log.error(e.getMessage(), e);
            }
        }
        return error;
    }
}
