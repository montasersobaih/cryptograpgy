package mj.crypto.hash;

import mj.crypto.enums.HashAlgorithm;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 02-07-2020
 */

public final class ByteHash extends AbstractHash<ByteBuffer> {

    public ByteHash(HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        super(algorithm);
    }

    public static Optional<byte[]> hash(HashAlgorithm algorithm, ByteBuffer input) {
        try {
            return new ByteHash(algorithm).add(input).finalizeHash().getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> hashTimes(HashAlgorithm algorithm, ByteBuffer input, int times) {
        try {
            return new ByteHash(algorithm).add(input).finalizeHash(times).getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> hash(HashAlgorithm algorithm, byte input) {
        try {
            return new ByteHash(algorithm).add(input).finalizeHash().getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> hashTimes(HashAlgorithm algorithm, byte input, int times) {
        try {
            return new ByteHash(algorithm).add(input).finalizeHash(times).getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> hash(HashAlgorithm algorithm, byte[] input) {
        try {
            return new ByteHash(algorithm).add(input).finalizeHash().getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> hashTimes(HashAlgorithm algorithm, byte[] input, int times) {
        try {
            return new ByteHash(algorithm).add(input).finalizeHash(times).getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> hash(HashAlgorithm algorithm, byte[] input, int offset, int limit) {
        try {
            return new ByteHash(algorithm).add(input, offset, limit).finalizeHash().getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> hashTimes(HashAlgorithm algorithm, byte[] input, int offset, int limit, int times) {
        try {
            return new ByteHash(algorithm).add(input, offset, limit).finalizeHash(times).getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public ByteHash add(ByteBuffer input) {
        digest.update(input);
        this.empty = false;
        return this;
    }

    public ByteHash add(byte input) {
        digest.update(input);
        this.empty = false;
        return this;
    }

    public ByteHash add(byte[] input) {
        digest.update(input);
        this.empty = false;
        return this;
    }

    public ByteHash add(byte[] input, int offset, int limit) {
        digest.update(input, offset, limit);
        this.empty = false;
        return this;
    }
}