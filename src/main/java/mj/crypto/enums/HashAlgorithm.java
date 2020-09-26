package mj.crypto.enums;

import java.security.NoSuchAlgorithmException;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 02-07-2020
 */

public enum HashAlgorithm {

    SHA_1("SHA-1", null),
    SHA_224("SHA-224", null),
    SHA_256("SHA-256", null),
    SHA_384("SHA-384", null),
    SHA_512("SHA-512", null),
    MD2("MD2", null),
    MD5("MD5", null);

    private String value;

    private NoSuchAlgorithmException exception;

    HashAlgorithm(String value, NoSuchAlgorithmException exception) {
        this.value = value;
        this.exception = exception;
    }

    public String getValue() {
        return value;
    }

    public NoSuchAlgorithmException getException() {
        return exception;
    }
}
