package mj.crypto.hash;

import mj.crypto.Result;
import mj.crypto.enums.MacAlgorithm;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Optional;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 04-07-2020
 */

public abstract class AbstractMac<T> implements Mac<T> {

    protected final javax.crypto.Mac mac;
    protected boolean empty = true;

    public AbstractMac(MacAlgorithm algorithm, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            (this.mac = javax.crypto.Mac.getInstance(algorithm.getValue())).init(key);
        } catch (NoSuchAlgorithmException e) {
            if (Objects.nonNull(algorithm.getException())) {
                throw algorithm.getException();
            }

            throw e;
        }
    }

    @Override
    public AbstractMac<T> clear() {
        this.mac.reset();
        this.empty = true;
        return this;
    }

    @Override
    public abstract AbstractMac<T> add(T input);

    @Override
    public Result finalizeMac(int times) {
        if (this.empty) {
            return Optional::empty;
        }

        this.empty = true;

        while (--times > 0) {
            this.mac.update(this.mac.doFinal());
        }

        return () -> Optional.of(this.mac.doFinal());
    }
}
