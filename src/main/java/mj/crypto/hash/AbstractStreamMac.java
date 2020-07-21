package mj.crypto.hash;

import mj.crypto.Result;
import mj.crypto.enums.MacAlgorithm;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.Optional;
import java.util.Queue;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 05-07-2020
 */

public abstract class AbstractStreamMac<T> extends AbstractMac<T> {

    protected Queue<byte[]> macs = new LinkedList<>();

    public AbstractStreamMac(MacAlgorithm algorithm, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        super(algorithm, key);
    }

    @Override
    public AbstractMac<T> clear() {
        this.macs = new LinkedList<>();
        return super.clear();
    }

    @Override
    public final Result finalizeMac(int times) {
        switch (this.macs.size()) {
            case 0:
                return Optional::empty;
            case 1:
                if (times > 1) {
                    this.mac.update(this.macs.poll());

                    while (--times > 1) {
                        this.mac.update(this.mac.doFinal());
                    }

                    return () -> Optional.of(this.mac.doFinal());
                } else {
                    return () -> Optional.ofNullable(this.macs.poll());
                }
            default:
                while (!this.macs.isEmpty()) {
                    this.mac.update(this.macs.poll());
                }

                while (--times > 1) {
                    this.mac.update(this.mac.doFinal());
                }

                return () -> Optional.of(this.mac.doFinal());
        }
    }
}
