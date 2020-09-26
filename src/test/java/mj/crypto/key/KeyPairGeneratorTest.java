package mj.crypto.key;

import mj.crypto.enums.KeyPairAlgorithm;
import mj.crypto.enums.KeySize;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 23-07-2020
 */

public class KeyPairGeneratorTest {

    private Class<? extends Throwable> invalidParameter = InvalidParameterException.class;

    @Test
    public void generateAsymmetricKeysUsingRSAAlgorithmTest() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairAlgorithm algorithm = KeyPairAlgorithm.RSA;

        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_32_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_256_BIT));

        Assert.assertNotNull(KeyPairGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertNotNull(KeyPairGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertNotNull(KeyPairGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertNotNull(KeyPairGenerator.generate(algorithm, KeySize.KEY_4096_BIT));


        //Using AlgorithmParameterSpec
        BigInteger[] integer = {RSAKeyGenParameterSpec.F0, RSAKeyGenParameterSpec.F4};
        for (BigInteger bigInteger : integer) {
            Assert.assertNotNull(KeyPairGenerator.generate(algorithm, new RSAKeyGenParameterSpec(512, bigInteger)));
            Assert.assertNotNull(KeyPairGenerator.generate(algorithm, new RSAKeyGenParameterSpec(1024, bigInteger)));
            Assert.assertNotNull(KeyPairGenerator.generate(algorithm, new RSAKeyGenParameterSpec(2048, bigInteger)));
            Assert.assertNotNull(KeyPairGenerator.generate(algorithm, new RSAKeyGenParameterSpec(4096, bigInteger)));
        }
    }

    @Test
    public void generateAsymmetricKeysUsingDSAAlgorithmTest() throws NoSuchAlgorithmException {
        KeyPairAlgorithm algorithm = KeyPairAlgorithm.DSA;

        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_32_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_64_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_128_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_168_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_256_BIT));

        Assert.assertNotNull(KeyPairGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertNotNull(KeyPairGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertNotNull(KeyPairGenerator.generate(algorithm, KeySize.KEY_2048_BIT));

        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_4096_BIT));


        //TODO AlgorithmParameterSpec
    }

    @Test
    public void generateAsymmetricKeysUsingECAlgorithmTest() throws NoSuchAlgorithmException {
        KeyPairAlgorithm algorithm = KeyPairAlgorithm.EC;

        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_16_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_32_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_40_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_56_BITS));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_64_BIT));

        Assert.assertNotNull(KeyPairGenerator.generate(algorithm, KeySize.KEY_112_BITS));
        Assert.assertNotNull(KeyPairGenerator.generate(algorithm, KeySize.KEY_128_BIT));

        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_168_BITS));

        Assert.assertNotNull(KeyPairGenerator.generate(algorithm, KeySize.KEY_192_BITS));
        Assert.assertNotNull(KeyPairGenerator.generate(algorithm, KeySize.KEY_256_BIT));

        Assert.assertThrows(ProviderException.class, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_512_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_1024_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_2048_BIT));
        Assert.assertThrows(invalidParameter, () -> KeyPairGenerator.generate(algorithm, KeySize.KEY_4096_BIT));

        //TODO AlgorithmParameterSpec
    }
}
