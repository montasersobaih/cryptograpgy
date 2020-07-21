package mj.crypto.key;

import mj.crypto.enums.KeyAlgorithm;
import mj.crypto.enums.KeySize;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 05-07-2020
 */

public final class KeyGenerator implements Generator<SecretKey> {

    private javax.crypto.KeyGenerator generator;

    public KeyGenerator(KeyAlgorithm algorithm) throws NoSuchAlgorithmException {
        this(algorithm, new SecureRandom());
    }

    public KeyGenerator(KeyAlgorithm algorithm, SecureRandom random) throws NoSuchAlgorithmException {
        (this.generator = javax.crypto.KeyGenerator.getInstance(algorithm.getValue())).init(random);
    }

    public KeyGenerator(KeyAlgorithm algorithm, KeySize size) throws NoSuchAlgorithmException {
        this(algorithm, size.getValue());
    }

    public KeyGenerator(KeyAlgorithm algorithm, int keySize) throws NoSuchAlgorithmException {
        (this.generator = javax.crypto.KeyGenerator.getInstance(algorithm.getValue())).init(keySize);
    }

    public KeyGenerator(KeyAlgorithm algorithm, KeySize size, SecureRandom random) throws NoSuchAlgorithmException {
        this(algorithm, size.getValue(), random);
    }

    public KeyGenerator(KeyAlgorithm algorithm, int keySize, SecureRandom random) throws NoSuchAlgorithmException {
        (this.generator = javax.crypto.KeyGenerator.getInstance(algorithm.getValue())).init(keySize, random);
    }

    @Override
    public SecretKey generate() {
        return this.generator.generateKey();
    }

    public static Optional<SecretKey> generate(KeyAlgorithm algorithm) {
        return KeyGenerator.generate(algorithm, (SecureRandom) null);
    }

    public static Optional<SecretKey> generate(KeyAlgorithm algorithm, SecureRandom random) {
        Optional<SecretKey> opKey = Optional.empty();

        try {
            opKey = Optional.of(new KeyGenerator(algorithm, random).generate());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return opKey;
    }

    public static Optional<SecretKey> generate(KeyAlgorithm algorithm, KeySize size) {
        return KeyGenerator.generate(algorithm, size.getValue());
    }

    public static Optional<SecretKey> generate(KeyAlgorithm algorithm, int keySize) {
        Optional<SecretKey> key = Optional.empty();

        try {
            key = Optional.of(new KeyGenerator(algorithm, keySize).generate());
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
        }

        return key;
    }

    public static Optional<SecretKey> generate(KeyAlgorithm algorithm, KeySize size, SecureRandom random) {
        return KeyGenerator.generate(algorithm, size.getValue(), random);
    }

    public static Optional<SecretKey> generate(KeyAlgorithm algorithm, int keySize, SecureRandom random) {
        Optional<SecretKey> key = Optional.empty();

        try {
            key = Optional.of(new KeyGenerator(algorithm, keySize, random).generate());
        } catch (NoSuchAlgorithmException e) {
            Logger.getGlobal().log(Level.WARNING, e.getMessage());
        }

        return key;
    }
}
