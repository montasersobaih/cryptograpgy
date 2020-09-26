package mj.crypto.key;

import mj.crypto.enums.KeyAlgorithm;
import mj.crypto.enums.KeySize;
import org.junit.Assert;
import org.junit.Test;

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 23-07-2020
 */

public class KeyGeneratorTest {

    private final Class<? extends Throwable> invalidParameter = InvalidParameterException.class;

    @Test
    public void generateSymmetricKeyUsingHmacSHA1Test() throws NoSuchAlgorithmException {
        KeyAlgorithm algorithm = KeyAlgorithm.HMAC_SHA1;

        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_32_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_256_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_4096_BIT));
    }

    @Test
    public void generateSymmetricKeyUsingHmacSHA224Test() throws NoSuchAlgorithmException {
        KeyAlgorithm algorithm = KeyAlgorithm.HMAC_SHA224;

        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_32_BIT));

        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_256_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_4096_BIT));
    }

    @Test
    public void generateSymmetricKeyUsingHmacSHA256Test() throws NoSuchAlgorithmException {
        KeyAlgorithm algorithm = KeyAlgorithm.HMAC_SHA256;

        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_32_BIT));

        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_256_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_4096_BIT));
    }

    @Test
    public void generateSymmetricKeyUsingHmacSHA384Test() throws NoSuchAlgorithmException {
        KeyAlgorithm algorithm = KeyAlgorithm.HMAC_SHA384;

        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_32_BIT));

        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_256_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_4096_BIT));
    }

    @Test
    public void generateSymmetricKeyUsingHmacSHA512Test() throws NoSuchAlgorithmException {
        KeyAlgorithm algorithm = KeyAlgorithm.HMAC_SHA512;

        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_32_BIT));

        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_256_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_4096_BIT));
    }

    @Test
    public void generateSymmetricKeyUsingHmacMD5Test() throws NoSuchAlgorithmException {
        KeyAlgorithm algorithm = KeyAlgorithm.HMAC_MD5;
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_32_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_256_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_4096_BIT));
    }

    @Test
    public void generateSymmetricKeyUsingDESTest() throws NoSuchAlgorithmException {
        KeyAlgorithm algorithm = KeyAlgorithm.DES;

        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_56_BITS));

        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_32_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_256_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_4096_BIT));
    }

    @Test
    public void generateSymmetricKeyUsingDESedeTest() throws NoSuchAlgorithmException {
        KeyAlgorithm algorithm = KeyAlgorithm.DESede;

        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_168_BITS));

        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_32_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_256_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_4096_BIT));
    }

    @Test
    public void generateSymmetricKeyUsingAESTest() throws NoSuchAlgorithmException {
        KeyAlgorithm algorithm = KeyAlgorithm.AES;

        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_256_BIT));

        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_32_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_4096_BIT));
    }

    @Test
    public void generateSymmetricKeyUsingRC2Test() throws NoSuchAlgorithmException {
        KeyAlgorithm algorithm = KeyAlgorithm.RC2;


        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_32_BIT));

        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_256_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_1024_BIT));

        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_4096_BIT));
    }

    @Test
    public void generateSymmetricKeyUsingRC4Test() throws NoSuchAlgorithmException {
        KeyAlgorithm algorithm = KeyAlgorithm.RC4;

        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_32_BIT));

        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_256_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_1024_BIT));

        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_4096_BIT));
    }

    @Test
    public void generateSymmetricKeyUsingBlowFishAlgorithmTest() throws NoSuchAlgorithmException {
        KeyAlgorithm algorithm = KeyAlgorithm.BLOW_FISH;

        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_16_BIT));

        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_32_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertNotNull(KeyGenerator.generate(algorithm, KeySize.KEY_256_BIT));

        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyGenerator.generate(algorithm, KeySize.KEY_4096_BIT));
    }
}
