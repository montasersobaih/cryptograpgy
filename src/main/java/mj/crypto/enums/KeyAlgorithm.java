package mj.crypto.enums;

import java.security.NoSuchAlgorithmException;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 07-07-2020
 */

public enum KeyAlgorithm {

    HMAC_SHA1("HmacSHA1", null),
    HMAC_SHA224("HmacSHA224", null),
    HMAC_SHA256("HmacSHA256", null),
    HMAC_SHA384("HmacSHA384", null),
    HMAC_SHA512("HmacSHA512", null),
    HMAC_MD5("HmacMD5", null),
    DES("DES", null),
    DESede("DESede", null),
    AES("AES", null),
    RC2("RC2", null),
    RC4("RC4", null),
    BLOW_FISH("BLOWFISH", null);

    private String value;

    private NoSuchAlgorithmException exception;

    KeyAlgorithm(String value, String message) {
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