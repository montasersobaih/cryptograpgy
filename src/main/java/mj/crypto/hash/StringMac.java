package mj.crypto.hash;

import mj.crypto.enums.MacAlgorithm;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 04-07-2020
 */

public final class StringMac extends AbstractMac<String> {

    public StringMac(MacAlgorithm algorithm, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        super(algorithm, key);
    }

    public static Optional<byte[]> mac(MacAlgorithm algorithm, SecretKey key, String input) {
        try {
            return new StringMac(algorithm, key).add(input).finalizeMac().getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }

    }

    public static Optional<byte[]> macTimes(MacAlgorithm algorithm, SecretKey key, String input, int times) {
        try {
            return new StringMac(algorithm, key).add(input).finalizeMac(times).getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> mac(MacAlgorithm algorithm, SecretKey key, String input, int start) {
        try {
            return new StringMac(algorithm, key).add(input, start).finalizeMac().getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> macTimes(MacAlgorithm algorithm, SecretKey key, String input, int start, int times) {
        try {
            return new StringMac(algorithm, key).add(input, start).finalizeMac(times).getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> mac(MacAlgorithm algorithm, SecretKey key, String input, int start, int end) {
        try {
            return new StringMac(algorithm, key).add(input, start, end).finalizeMac().getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> macTimes(
            MacAlgorithm algorithm, SecretKey key, String input, int start, int end, int times
    ) {
        try {
            return new StringMac(algorithm, key).add(input, start, end).finalizeMac(times).getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public StringMac add(String input) {
        if (Objects.isNull(input)) {
            throw new IllegalArgumentException("Input must not be null");
        }

        this.mac.update(input.getBytes());
        this.empty = false;
        return this;
    }

    public StringMac add(String input, int start) {
        if (Objects.isNull(input)) {
            throw new IllegalArgumentException("Input must not be null");
        }

        this.mac.update(input.substring(start).getBytes());
        this.empty = false;
        return this;
    }

    public StringMac add(String input, int start, int end) {
        if (Objects.isNull(input)) {
            throw new IllegalArgumentException("Input must not be null");
        }

        this.mac.update(input.substring(start, end).getBytes());
        this.empty = false;
        return this;
    }
}
