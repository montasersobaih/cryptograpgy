package mj.crypto.hash;

import mj.crypto.enums.MacAlgorithm;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 05-07-2020
 */

public final class InputStreamMac extends AbstractStreamMac<InputStream> {

    public InputStreamMac(MacAlgorithm algorithm, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        super(algorithm, key);
    }

    public static Optional<byte[]> mac(MacAlgorithm algorithm, SecretKey key, InputStream input) {
        try {
            return new InputStreamMac(algorithm, key).add(input).finalizeMac().getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }

    }

    public static Optional<byte[]> macTimes(MacAlgorithm algorithm, SecretKey key, InputStream input, int times) {
        try {
            return new InputStreamMac(algorithm, key).add(input).finalizeMac(times).getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public InputStreamMac add(InputStream input) {
        if (Objects.isNull(input)) {
            throw new IllegalArgumentException("Input must not be null");
        }

        try (InputStream inputStream = input) {
            byte $byte;
            while (($byte = (byte) inputStream.read()) > -1) {
                this.mac.update($byte);
            }

            this.macs.offer(this.mac.doFinal());
        } catch (IOException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
        }

        return this;
    }
}
