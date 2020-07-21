package mj.crypto.hash;

import mj.crypto.enums.HashAlgorithm;

import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 02-07-2020
 */

public final class StringHash extends AbstractHash<String> {

    public StringHash(HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        super(algorithm);
    }

    public static Optional<byte[]> hash(HashAlgorithm algorithm, String input) {
        try {
            return new StringHash(algorithm).add(input).finalizeHash().getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }

    }

    public static Optional<byte[]> hashTimes(HashAlgorithm algorithm, String input, int times) {
        try {
            return new StringHash(algorithm).add(input).finalizeHash(times).getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> hash(HashAlgorithm algorithm, String input, int start) {
        try {
            return new StringHash(algorithm).add(input, start).finalizeHash().getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> hashTimes(HashAlgorithm algorithm, String input, int start, int times) {
        try {
            return new StringHash(algorithm).add(input, start).finalizeHash(times).getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> hash(HashAlgorithm algorithm, String input, int start, int end) {
        try {
            return new StringHash(algorithm).add(input, start, end).finalizeHash().getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<byte[]> hashTimes(HashAlgorithm algorithm, String input, int start, int end, int times) {
        try {
            return new StringHash(algorithm).add(input, start, end).finalizeHash(times).getResult();
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public StringHash add(String input) {
        digest.update(input.getBytes());
        this.empty = false;
        return this;
    }

    public StringHash add(String input, int start) {
        digest.update(input.substring(start).getBytes());
        this.empty = false;
        return this;
    }

    public StringHash add(String input, int start, int end) {
        digest.update(input.substring(start, end).getBytes());
        this.empty = false;
        return this;
    }
}
