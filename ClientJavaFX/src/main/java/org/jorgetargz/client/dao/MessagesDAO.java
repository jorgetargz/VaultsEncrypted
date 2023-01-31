package org.jorgetargz.client.dao;

import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import org.jorgetargz.utils.modelo.Message;

import java.util.List;

public interface MessagesDAO {

    Single<Either<String, List<Message>>> getAll(String vaultName, String username, String password);

    Single<Either<String, Message>> save(Message message, String password);

    Single<Either<String, Message>> update(Message message, String password);

    Single<Either<String, Boolean>> delete(int messageId);
}
