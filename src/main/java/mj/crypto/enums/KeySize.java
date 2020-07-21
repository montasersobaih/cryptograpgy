package mj.crypto.enums;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 07-07-2020
 */

public enum KeySize {

    KEY_16_BIT(16),
    KEY_32_BIT(32),
    KEY_40_BIT(40),
    KEY_56_BITS(56),
    KEY_64_BIT(64),
    KEY_112_BITS(112),
    KEY_128_BIT(128),
    KEY_168_BITS(168),
    KEY_192_BITS(192),
    KEY_256_BIT(256),
    KEY_512_BIT(512),
    KEY_1024_BIT(1024),
    KEY_2048_BIT(2048),
    KEY_4096_BIT(4096);

    private int value;

    KeySize(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}