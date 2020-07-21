package mj.crypto.hash;

import mj.crypto.enums.MacAlgorithm;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
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

public final class ByteMac extends AbstractMac<ByteBuffer> {

    public ByteMac(MacAlgorithm algorithm, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        super(algorithm, key);
    }

    public static Optional<byte[]> mac(MacAlgorithm algorithm, SecretKey key, ByteBuffer input) {
        try {
            return new ByteMac(algorithm, key).add(input).finalizeMac().getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> macTimes(MacAlgorithm algorithm, SecretKey key, ByteBuffer input, int times) {
        try {
            return new ByteMac(algorithm, key).add(input).finalizeMac(times).getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> mac(MacAlgorithm algorithm, SecretKey key, byte input) {
        try {
            return new ByteMac(algorithm, key).add(input).finalizeMac().getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> macTimes(MacAlgorithm algorithm, SecretKey key, byte input, int times) {
        try {
            return new ByteMac(algorithm, key).add(input).finalizeMac(times).getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> mac(MacAlgorithm algorithm, SecretKey key, byte[] input) {
        try {
            return new ByteMac(algorithm, key).add(input).finalizeMac().getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> macTimes(MacAlgorithm algorithm, SecretKey key, byte[] input, int times) {
        try {
            return new ByteMac(algorithm, key).add(input).finalizeMac(times).getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> mac(MacAlgorithm algorithm, SecretKey key, byte[] input, int offset, int limit) {
        try {
            return new ByteMac(algorithm, key).add(input, offset, limit).finalizeMac().getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> macTimes(
            MacAlgorithm algorithm, SecretKey key, byte[] input, int offset, int limit, int times
    ) {
        try {
            return new ByteMac(algorithm, key).add(input, offset, limit).finalizeMac(times).getResult();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public ByteMac add(ByteBuffer input) {
        if (Objects.isNull(input)) {
            throw new IllegalArgumentException("Input must not be null");
        }

        this.mac.update(input);
        this.empty = false;
        return this;
    }

    public ByteMac add(byte input) {
        this.mac.update(input);
        this.empty = false;
        return this;
    }

    public ByteMac add(byte[] input) {
        if (Objects.isNull(input)) {
            throw new IllegalArgumentException("Input must not be null");
        }

        this.mac.update(input);
        this.empty = false;
        return this;
    }

    public ByteMac add(byte[] input, int offset, int limit) {
        if (Objects.isNull(input)) {
            throw new IllegalArgumentException("Input must not be null");
        }

        this.mac.update(input, offset, limit);
        this.empty = false;
        return this;
    }
}