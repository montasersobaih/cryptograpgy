package mj.crypto.key;

import mj.crypto.enums.KeyPairAlgorithm;
import mj.crypto.enums.KeySize;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 06-07-2020
 */

public final class KeyPairGenerator implements Generator<KeyPair> {

    private java.security.KeyPairGenerator generator;

    public KeyPairGenerator(KeyPairAlgorithm algorithm, KeySize size) throws NoSuchAlgorithmException {
        this(algorithm, size.getValue());
    }

    public KeyPairGenerator(KeyPairAlgorithm algorithm, int keySize) throws NoSuchAlgorithmException {
        (this.generator = java.security.KeyPairGenerator.getInstance(algorithm.getValue())).initialize(keySize);
    }

    public KeyPairGenerator(
            KeyPairAlgorithm algorithm, AlgorithmParameterSpec spec
    ) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        (this.generator = java.security.KeyPairGenerator.getInstance(algorithm.getValue())).initialize(spec);
    }

    public KeyPairGenerator(
            KeyPairAlgorithm algorithm, KeySize size, SecureRandom random
    ) throws NoSuchAlgorithmException {
        this(algorithm, size.getValue(), random);
    }

    public KeyPairGenerator(
            KeyPairAlgorithm algorithm, int keySize, SecureRandom random
    ) throws NoSuchAlgorithmException {
        (this.generator = java.security.KeyPairGenerator.getInstance(algorithm.getValue())).initialize(keySize, random);
    }

    public KeyPairGenerator(
            KeyPairAlgorithm algorithm, AlgorithmParameterSpec spec, SecureRandom random
    ) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        (this.generator = java.security.KeyPairGenerator.getInstance(algorithm.getValue())).initialize(spec, random);
    }

    public static KeyPair generate(KeyPairAlgorithm algorithm, KeySize size) throws NoSuchAlgorithmException {
        return new KeyPairGenerator(algorithm, size).generate();
    }

    public static KeyPair generate(KeyPairAlgorithm algorithm, int keySize) throws NoSuchAlgorithmException {
        return new KeyPairGenerator(algorithm, keySize).generate();
    }

    public static KeyPair generate(
            KeyPairAlgorithm algorithm, AlgorithmParameterSpec spec
    ) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return new KeyPairGenerator(algorithm, spec).generate();
    }

    public static KeyPair generate(
            KeyPairAlgorithm algorithm, KeySize size, SecureRandom random
    ) throws NoSuchAlgorithmException {
        return new KeyPairGenerator(algorithm, size, random).generate();
    }

    public static KeyPair generate(
            KeyPairAlgorithm algorithm, int keySize, SecureRandom random
    ) throws NoSuchAlgorithmException {
        return new KeyPairGenerator(algorithm, keySize, random).generate();
    }

    public static KeyPair generate(
            KeyPairAlgorithm algorithm, AlgorithmParameterSpec spec, SecureRandom random
    ) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return new KeyPairGenerator(algorithm, spec, random).generate();
    }

    @Override
    public KeyPair generate() {
        return this.generator.generateKeyPair();
    }
}
