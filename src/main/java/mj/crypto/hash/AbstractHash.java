package mj.crypto.hash;

import mj.crypto.Result;
import mj.crypto.enums.HashAlgorithm;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Optional;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 02-07-2020
 */

public abstract class AbstractHash<T> implements Hash<T> {

    protected final MessageDigest digest;
    protected boolean empty = true;

    public AbstractHash(HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        try {
            this.digest = MessageDigest.getInstance(algorithm.getValue());
        } catch (NoSuchAlgorithmException e) {
            if (Objects.nonNull(algorithm.getException())) {
                throw algorithm.getException();
            }

            throw e;
        }
    }

    @Override
    public AbstractHash<T> clear() {
        this.empty = true;
        this.digest.reset();
        return this;
    }

    @Override
    public abstract AbstractHash<T> add(T input);

    @Override
    public Result finalizeHash(int times) {
        if (this.empty) {
            return Optional::empty;
        }

        this.empty = true;

        while (--times > 0) {
            this.digest.update(this.digest.digest());
        }

        return () -> Optional.of(this.digest.digest());
    }
}
