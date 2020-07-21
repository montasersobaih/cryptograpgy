package mj.crypto.hash;

import mj.crypto.enums.KeyAlgorithm;
import mj.crypto.enums.MacAlgorithm;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
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
public class ByteMacTest {

    private static SecretKey key;
    private final List<byte[]> bytes = Arrays.asList(
            "This sentence will be mac".getBytes(),
            "This is my sample mac".getBytes(),
            "This is a unit testing class".getBytes()
    );
    @Parameter
    public MacAlgorithm algorithm;

    @Parameters
    public static MacAlgorithm[] data() {
        return MacAlgorithm.values();
    }

    @BeforeClass
    public static void generateKey() throws NoSuchAlgorithmException {
        key = KeyGenerator.getInstance(KeyAlgorithm.DES.getValue()).generateKey();
    }

    @Test
    public void macByteTest() {
        Assert.assertTrue(ByteMac.mac(algorithm, key, Byte.MAX_VALUE).isPresent());
        Assert.assertTrue(ByteMac.macTimes(algorithm, key, Byte.MAX_VALUE, 2).isPresent());
    }

    @Test
    public void macNullByteArrayTest() {
        Class<? extends Throwable> clz = IllegalArgumentException.class;
        Assert.assertThrows(clz, () -> ByteMac.mac(algorithm, key, (ByteBuffer) null));
        Assert.assertThrows(clz, () -> ByteMac.mac(algorithm, key, (byte[]) null));
    }

    @Test
    public void macNullByteArrayMoreTimesTest() {
        Class<? extends Throwable> clz = IllegalArgumentException.class;
        Assert.assertThrows(clz, () -> ByteMac.macTimes(algorithm, key, (ByteBuffer) null, 2));
        Assert.assertThrows(clz, () -> ByteMac.macTimes(algorithm, key, (byte[]) null, 2));
    }

    @Test
    public void hashWithoutPassingValueTest() throws NoSuchAlgorithmException, InvalidKeyException {
        ByteMac hash = new ByteMac(algorithm, key);
        Assert.assertFalse(hash.finalizeMac().getResult().isPresent());
        Assert.assertFalse(hash.finalizeMac(5).getResult().isPresent());
    }

    @Test
    public void hashWithPassingValueMoreTimesTest() throws NoSuchAlgorithmException, InvalidKeyException {
        ByteMac hash = new ByteMac(algorithm, key);
        Assert.assertTrue(hash.add(new byte[0]).finalizeMac().getResult().isPresent());
        Assert.assertTrue(hash.add(new byte[0]).finalizeMac(5).getResult().isPresent());
    }

    @Test
    public void macEmptyByteArrayTest() {
        Assert.assertTrue(ByteMac.mac(algorithm, key, new byte[0]).isPresent());
        Assert.assertThrows(IllegalArgumentException.class, () -> ByteMac.mac(algorithm, key, new byte[0], 0, 1));
    }

    @Test
    public void macEmptyByteArrayMoreTimesTest() {
        Assert.assertTrue(ByteMac.macTimes(algorithm, key, new byte[0], 2).isPresent());
        Assert.assertThrows(IllegalArgumentException.class, () -> ByteMac.macTimes(algorithm, key, new byte[0], 0, 1, 2));
    }

    @Test
    public void macByteArrayTest() {
        byte[] bytes = this.bytes.get(0);

        Class<? extends Throwable> clz = IllegalArgumentException.class;
        Assert.assertTrue(ByteMac.mac(algorithm, key, bytes).isPresent());
        Assert.assertTrue(ByteMac.mac(algorithm, key, bytes, 0, bytes.length).isPresent());
        Assert.assertThrows(clz, () -> ByteMac.mac(algorithm, key, bytes, 5, bytes.length));
    }

    @Test
    public void macByteArrayMoreTimesTest() {
        byte[] bytes = this.bytes.get(0);

        Class<? extends Throwable> clz = IllegalArgumentException.class;
        Assert.assertTrue(ByteMac.macTimes(algorithm, key, bytes, 2).isPresent());
        Assert.assertTrue(ByteMac.macTimes(algorithm, key, bytes, 0, bytes.length, 2).isPresent());
        Assert.assertThrows(clz, () -> ByteMac.macTimes(algorithm, key, bytes, 5, bytes.length, 2));
    }

    @Test
    public void macByteAndCheckResultTest() throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(key);

        byte b = Byte.MAX_VALUE;
        Assert.assertArrayEquals(ByteMac.mac(algorithm, key, b).get(), mac.doFinal(new byte[]{b}));
    }

    @Test
    public void macByteMoreTimesAndCheckResultTest() throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(key);

        byte b = Byte.MAX_VALUE;
        for (int times = 0; times < 5; times++) {
            mac.update(b);

            for (int j = 0; j < times - 1; j++) {
                mac.update(mac.doFinal());
            }

            Assert.assertArrayEquals(ByteMac.macTimes(algorithm, key, b, times).get(), mac.doFinal());
        }
    }

    @Test
    public void macListOfBytesAndCheckResultTest() throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(key);

        ByteMac byteMac = new ByteMac(algorithm, key);

        for (byte[] arr : bytes) {
            byteMac.add(arr);
            mac.update(arr);
        }

        Assert.assertArrayEquals(byteMac.finalizeMac().getResult().get(), mac.doFinal());
    }

    @Test
    public void macListOfBytesMoreTimesAndCheckResultTest() throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(key);

        ByteMac byteMac = new ByteMac(algorithm, key);

        for (byte[] arr : bytes) {
            byteMac.add(arr);
            mac.update(arr);
        }

        int times = 3;
        for (int i = 0; i < times - 1; i++) {
            mac.update(mac.doFinal());
        }

        Assert.assertArrayEquals(byteMac.finalizeMac(times).getResult().get(), mac.doFinal());

        Mac mac2 = Mac.getInstance(algorithm.getValue());
        mac2.init(key);

        for (byte[] arr : bytes) {
            ByteMac.macTimes(algorithm, key, arr, times).ifPresent(byteMac::add);
            mac2.update(arr);

            for (int i = 0; i < times - 1; i++) {
                mac2.update(mac2.doFinal());
            }

            mac.update(mac2.doFinal());
        }

        Assert.assertArrayEquals(byteMac.finalizeMac().getResult().get(), mac.doFinal());

        for (byte[] arr : bytes) {
            byteMac.add(arr);
        }

        Assert.assertFalse(byteMac.clear().finalizeMac().getResult().isPresent());
    }
}
