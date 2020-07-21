package mj.crypto.hash;

import mj.crypto.Result;
import mj.crypto.enums.HashAlgorithm;

import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.Optional;
import java.util.Queue;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 03-07-2020
 */

public abstract class AbstractStreamHash<T> extends AbstractHash<T> {

    protected Queue<byte[]> hashes = new LinkedList<>();

    public AbstractStreamHash(HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        super(algorithm);
    }

    @Override
    public AbstractHash<T> clear() {
        this.hashes = new LinkedList<>();
        return super.clear();
    }

    @Override
    public final Result finalizeHash(int times) {
        switch (this.hashes.size()) {
            case 0:
                return Optional::empty;
            case 1:
                if (times > 1) {
                    this.digest.update(this.hashes.poll());

                    while (--times > 1) {
                        this.digest.update(this.digest.digest());
                    }

                    return () -> Optional.of(this.digest.digest());
                } else {
                    return () -> Optional.ofNullable(this.hashes.poll());
                }
            default:
                while (!this.hashes.isEmpty()) {
                    this.digest.update(this.hashes.poll());
                }

                while (--times > 1) {
                    this.digest.update(this.digest.digest());
                }

                return () -> Optional.of(this.digest.digest());
        }
    }
}
