package mj.crypto.enums;

import java.security.NoSuchAlgorithmException;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 04-07-2020
 */

public enum MacAlgorithm {

    SSL_MAC_SHA1("SslMacSHA1", null),
    SSL_MAC_MD5("SslMacMD5", null),
    HMAC_SHA1("HmacSHA1", null),
    HMAC_SHA224("HmacSHA224", null),
    HMAC_SHA384("HmacSHA384", null),
    HMAC_SHA512("HmacSHA512", null),
    HMAC_MD5("HmacMD5", null);

    private String value;

    private NoSuchAlgorithmException exception;

    MacAlgorithm(String value, NoSuchAlgorithmException exception) {
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
