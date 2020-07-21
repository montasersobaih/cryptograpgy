package mj.crypto.hash;

import mj.crypto.enums.HashAlgorithm;

import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 03-07-2020
 */

public final class InputStreamHash extends AbstractStreamHash<InputStream> {

    public InputStreamHash(HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        super(algorithm);
    }

    public static Optional<byte[]> hash(HashAlgorithm algorithm, InputStream input) {
        try {
            return new InputStreamHash(algorithm).add(input).finalizeHash().getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }

    }

    public static Optional<byte[]> hashTimes(HashAlgorithm algorithm, InputStream input, int times) {
        try {
            return new InputStreamHash(algorithm).add(input).finalizeHash(times).getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public InputStreamHash add(InputStream input) {
        try (InputStream inputStream = new DigestInputStream(input, this.digest)) {
            while (inputStream.read() > -1) ;

            this.hashes.offer(this.digest.digest());
        } catch (IOException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
        }

        return this;
    }
}
