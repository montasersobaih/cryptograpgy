package mj.crypto.enums;

import java.security.NoSuchAlgorithmException;

public enum KeyPairAlgorithm {

    RSA("RSA", null),
    DSA("DSA", null),
    EC("EC", null),
    DH("DiffieHellman", null);

    private String value;

    private NoSuchAlgorithmException exception;

    KeyPairAlgorithm(String value, String message) {
        this.value = value;
        this.exception = new NoSuchAlgorithmException(message);
    }

    public String getValue() {
        return value;
    }

    public NoSuchAlgorithmException getException() {
        return exception;
    }
}
