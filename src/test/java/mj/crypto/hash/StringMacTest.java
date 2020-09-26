package mj.crypto.hash;

import mj.crypto.enums.KeyAlgorithm;
import mj.crypto.enums.MacAlgorithm;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 04-07-2020
 */

@RunWith(Parameterized.class)
public class StringMacTest {

    private static SecretKey key;
    private final List<String> strings = Arrays.asList(
            "",
            "This sentence is for hashing",
            "This is my sample hashing",
            "This is a unit testing class"
    );
    private MacAlgorithm algorithm;

    public StringMacTest(MacAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    @Parameterized.Parameters
    public static Object[] data() {
        return MacAlgorithm.values();
    }

    @BeforeClass
    public static void generateKey() throws NoSuchAlgorithmException {
        key = KeyGenerator.getInstance(KeyAlgorithm.DES.getValue()).generateKey();
    }

    @Test
    public void macStringTest() {
        final String string = strings.get(1);
        final int length = string.length();

        Assert.assertTrue(StringMac.mac(algorithm, key, string).isPresent());
        Assert.assertTrue(StringMac.mac(algorithm, key, string, length - 6).isPresent());
        Assert.assertTrue(StringMac.mac(algorithm, key, string, length - 6, length).isPresent());
        Assert.assertTrue(StringMac.mac(algorithm, key, string, length).isPresent());
        Assert.assertTrue(StringMac.mac(algorithm, key, string, length, length).isPresent());

        Class<StringIndexOutOfBoundsException> clz = StringIndexOutOfBoundsException.class;
        Assert.assertThrows(clz, () -> StringMac.mac(algorithm, key, string, length + 1));
        Assert.assertThrows(clz, () -> StringMac.mac(algorithm, key, string, length, length + 1));
        Assert.assertThrows(clz, () -> StringMac.mac(algorithm, key, string, length - 5, length + 7));
    }

    @Test
    public void hashNullStringTest() {
        Class<? extends Throwable> clz = IllegalArgumentException.class;
        Assert.assertThrows(clz, () -> StringMac.mac(algorithm, key, null));
        Assert.assertThrows(clz, () -> StringMac.mac(algorithm, key, null, 0));
        Assert.assertThrows(clz, () -> StringMac.mac(algorithm, key, null, 0, 1));

    }

    @Test
    public void hashNullStringMoreTimesTest() {
        Class<? extends Throwable> clz = IllegalArgumentException.class;
        Assert.assertThrows(clz, () -> StringMac.macTimes(algorithm, key, null, 5));
        Assert.assertThrows(clz, () -> StringMac.macTimes(algorithm, key, null, 0, 5));
        Assert.assertThrows(clz, () -> StringMac.macTimes(algorithm, key, null, 0, 1, 5));
    }

    @Test
    public void hashWithoutPassingValueTest() throws NoSuchAlgorithmException, InvalidKeyException {
        StringMac hash = new StringMac(algorithm, key);
        Assert.assertFalse(hash.finalizeMac().getResult().isPresent());
        Assert.assertFalse(hash.finalizeMac(5).getResult().isPresent());
    }

    @Test
    public void hashWithPassingValueMoreTimesTest() throws NoSuchAlgorithmException, InvalidKeyException {
        StringMac hash = new StringMac(algorithm, key);

        String empty = strings.get(0);
        Assert.assertTrue(hash.add(empty).finalizeMac().getResult().isPresent());
        Assert.assertTrue(hash.add(empty).finalizeMac(5).getResult().isPresent());
    }

    @Test
    public void hashEmptyStringTest() {
        Assert.assertTrue(StringMac.mac(algorithm, key, "").isPresent());
        Assert.assertTrue(StringMac.mac(algorithm, key, "", 0).isPresent());
        Assert.assertTrue(StringMac.mac(algorithm, key, "", 0, 0).isPresent());

        Class<StringIndexOutOfBoundsException> clz = StringIndexOutOfBoundsException.class;
        Assert.assertThrows(clz, () -> StringMac.mac(algorithm, key, "", -1));
        Assert.assertThrows(clz, () -> StringMac.mac(algorithm, key, "", -1, 0));
        Assert.assertThrows(clz, () -> StringMac.mac(algorithm, key, "", 0, 1));
        Assert.assertThrows(clz, () -> StringMac.mac(algorithm, key, "", 1));
        Assert.assertThrows(clz, () -> StringMac.mac(algorithm, key, "", 1, 1));
    }

    @Test
    public void hashEmptyStringMoreTimesTest() {
        Assert.assertTrue(StringMac.macTimes(algorithm, key, "", -1).isPresent());
        Assert.assertTrue(StringMac.macTimes(algorithm, key, "", 0).isPresent());
        Assert.assertTrue(StringMac.macTimes(algorithm, key, "", 4).isPresent());
        Assert.assertTrue(StringMac.macTimes(algorithm, key, "", 0, 4).isPresent());
        Assert.assertTrue(StringMac.macTimes(algorithm, key, "", 0, 0, -2).isPresent());
        Assert.assertTrue(StringMac.macTimes(algorithm, key, "", 0, 0, 1000).isPresent());
    }

    @Test
    public void hashStringAndCheckResultTest() throws NoSuchAlgorithmException, InvalidKeyException {
        final String string = strings.get(1);
        final int length = string.length();

        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(key);

        Assert.assertArrayEquals(
                StringMac.mac(algorithm, key, string).get(),
                mac.doFinal(string.getBytes())
        );

        Assert.assertArrayEquals(
                StringMac.mac(algorithm, key, string, length - 2).get(),
                mac.doFinal(string.substring(length - 2).getBytes())
        );

        Assert.assertArrayEquals(
                StringMac.mac(algorithm, key, string, length - 2, length - 1).get(),
                mac.doFinal(string.substring(length - 2, length - 1).getBytes())
        );
    }

    @Test
    public void hashListOfStringAndCheckResultTest() throws NoSuchAlgorithmException, InvalidKeyException {
        StringMac stringMac = new StringMac(algorithm, key);

        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(key);

        for (String string : strings) {
            stringMac.add(string);
            mac.update(string.getBytes());
        }

        Assert.assertArrayEquals(stringMac.finalizeMac().getResult().get(), mac.doFinal());

        for (String string : strings) {
            stringMac.add(string, string.length() / 2);
            mac.update(string.substring(string.length() / 2).getBytes());
        }

        Assert.assertArrayEquals(stringMac.finalizeMac().getResult().get(), mac.doFinal());

        for (String string : strings) {
            int length = string.length();
            int from = length != 0 ? length / 2 : length;
            int to = length != 0 ? length / 2 + 1 : length;
            stringMac.add(string, from, to);
            mac.update(string.substring(from, to).getBytes());
        }

        Assert.assertArrayEquals(stringMac.finalizeMac().getResult().get(), mac.doFinal());

        for (String string : strings) {
            int length = string.length();
            int from = length != 0 ? length / 2 : length;
            int to = length != 0 ? length / 2 + 1 : length;
            stringMac.add(string, from, to);
        }

        Assert.assertFalse(stringMac.clear().finalizeMac().getResult().isPresent());
        Assert.assertFalse(stringMac.finalizeMac().getResult().isPresent());
    }
}
