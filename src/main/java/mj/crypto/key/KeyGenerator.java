package mj.crypto.key;

import mj.crypto.enums.KeyAlgorithm;
import mj.crypto.enums.KeySize;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 08-07-2020
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

    public static SecretKey generate(KeyAlgorithm algorithm) throws NoSuchAlgorithmException {
        return KeyGenerator.generate(algorithm, (SecureRandom) null);
    }

    public static SecretKey generate(KeyAlgorithm algorithm, SecureRandom random) throws NoSuchAlgorithmException {
        return new KeyGenerator(algorithm, random).generate();
    }

    public static SecretKey generate(KeyAlgorithm algorithm, KeySize size) throws NoSuchAlgorithmException {
        return KeyGenerator.generate(algorithm, size.getValue());
    }

    public static SecretKey generate(KeyAlgorithm algorithm, int keySize) throws NoSuchAlgorithmException {
        return new KeyGenerator(algorithm, keySize).generate();
    }

    public static SecretKey generate(KeyAlgorithm algorithm, KeySize size, SecureRandom random) throws NoSuchAlgorithmException {
        return KeyGenerator.generate(algorithm, size.getValue(), random);
    }

    public static SecretKey generate(KeyAlgorithm algorithm, int keySize, SecureRandom random) throws NoSuchAlgorithmException {
        return new KeyGenerator(algorithm, keySize, random).generate();
    }
}
