package mj.crypto.hash;

import mj.crypto.enums.HashAlgorithm;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 02-07-2020
 */

@RunWith(Parameterized.class)
public class ByteHashTest {

    private final List<byte[]> bytes = Arrays.asList(
            "".getBytes(),
            "This sentence is for hashing".getBytes(),
            "This is my sample hashing".getBytes(),
            "This is a unit testing class".getBytes()
    );

    @Parameter
    public HashAlgorithm algorithm;

    @Parameters
    public static HashAlgorithm[] data() {
        return HashAlgorithm.values();
    }

    @Test
    public void hashByteTest() {
        Assert.assertTrue(ByteHash.hash(algorithm, Byte.MAX_VALUE).isPresent());
        Assert.assertTrue(ByteHash.hashTimes(algorithm, Byte.MAX_VALUE, 2).isPresent());
    }

    @Test
    public void hashNullByteArrayTest() {
        Class<? extends Throwable> clz = NullPointerException.class;
        Assert.assertThrows(clz, () -> ByteHash.hash(algorithm, (ByteBuffer) null));
        Assert.assertThrows(clz, () -> ByteHash.hash(algorithm, (byte[]) null));
    }

    @Test
    public void hashNullByteArrayMoreTimesTest() {
        Class<? extends Throwable> clz = NullPointerException.class;
        Assert.assertThrows(clz, () -> ByteHash.hashTimes(algorithm, (ByteBuffer) null, 2));
        Assert.assertThrows(clz, () -> ByteHash.hashTimes(algorithm, (byte[]) null, 2));
    }

    @Test
    public void hashWithoutPassingValueTest() throws NoSuchAlgorithmException {
        ByteHash hash = new ByteHash(algorithm);
        Assert.assertFalse(hash.finalizeHash().getResult().isPresent());
        Assert.assertFalse(hash.finalizeHash(5).getResult().isPresent());
    }

    @Test
    public void hashWithPassingValueMoreTimesTest() throws NoSuchAlgorithmException {
        ByteHash hash = new ByteHash(algorithm);
        Assert.assertTrue(hash.add(new byte[0]).finalizeHash().getResult().isPresent());
        Assert.assertTrue(hash.add(new byte[0]).finalizeHash(5).getResult().isPresent());
    }

    @Test
    public void hashEmptyByteArrayTest() {
        Assert.assertTrue(ByteHash.hash(algorithm, new byte[0]).isPresent());
        Assert.assertThrows(IllegalArgumentException.class, () -> ByteHash.hash(algorithm, new byte[0], 0, 1));
    }

    @Test
    public void hashEmptyByteArrayMoreTimesTest() {
        Assert.assertTrue(ByteHash.hashTimes(algorithm, new byte[0], 2).isPresent());
        Assert.assertThrows(IllegalArgumentException.class, () -> ByteHash.hash(algorithm, new byte[0], 0, 1));
    }

    @Test
    public void hashEmptyByteArrayAndCheckResultTest() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());

        Assert.assertArrayEquals(ByteHash.hash(algorithm, new byte[0]).get(), digest.digest());
        Assert.assertThrows(IllegalArgumentException.class, () -> ByteHash.hash(algorithm, new byte[0], 0, 1));
    }

    @Test
    public void hashEmptyByteArrayMoreTimesAndCheckResultTest() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());

        int times = 2;
        for (int i = 0; i < times - 1; i++) {
            digest.update(digest.digest());
        }

        Assert.assertArrayEquals(ByteHash.hashTimes(algorithm, new byte[0], 2).get(), digest.digest());
        Assert.assertThrows(IllegalArgumentException.class, () -> ByteHash.hash(algorithm, new byte[0], 0, 1));
    }

    @Test
    public void hashByteArrayTest() {
        Class<? extends Throwable> clz = IllegalArgumentException.class;

        byte[] bytes = this.bytes.get(0);
        Assert.assertTrue(ByteHash.hash(algorithm, bytes).isPresent());
        Assert.assertTrue(ByteHash.hash(algorithm, bytes, 0, bytes.length).isPresent());
        Assert.assertThrows(clz, () -> ByteHash.hash(algorithm, bytes, 5, bytes.length));
    }

    @Test
    public void hashByteArrayMoreTimesTest() {
        Class<? extends Throwable> clz = IllegalArgumentException.class;

        byte[] bytes = this.bytes.get(0);
        Assert.assertTrue(ByteHash.hashTimes(algorithm, bytes, 2).isPresent());
        Assert.assertTrue(ByteHash.hashTimes(algorithm, bytes, 0, bytes.length, 2).isPresent());
        Assert.assertThrows(clz, () -> ByteHash.hashTimes(algorithm, bytes, 5, bytes.length, 2));
    }

    @Test
    public void hashByteAndCheckResultTest() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());

        byte b = Byte.MAX_VALUE;
        Assert.assertArrayEquals(ByteHash.hash(algorithm, b).get(), digest.digest(new byte[]{b}));
    }

    @Test
    public void hashByteMoreTimesAndCheckResultTest() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());

        byte b = Byte.MAX_VALUE;
        for (int times = 0; times < 5; times++) {
            digest.update(b);

            for (int j = 0; j < times - 1; j++) {
                digest.update(digest.digest());
            }

            Assert.assertArrayEquals(ByteHash.hashTimes(algorithm, b, times).get(), digest.digest());
        }
    }

    @Test
    public void hashListOfBytesAndCheckResultTest() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());
        ByteHash hash = new ByteHash(algorithm);

        for (byte[] arr : bytes) {
            hash.add(arr);
            digest.update(arr);
        }

        Assert.assertArrayEquals(hash.finalizeHash().getResult().get(), digest.digest());
    }

    @Test
    public void hashListOfBytesMoreTimesAndCheckResultTest() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());
        ByteHash hash = new ByteHash(algorithm);

        for (byte[] arr : bytes) {
            hash.add(arr);
            digest.update(arr);
        }

        int times = 3;
        for (int i = 0; i < times - 1; i++) {
            digest.update(digest.digest());
        }

        Assert.assertArrayEquals(hash.finalizeHash(times).getResult().get(), digest.digest());

        MessageDigest digest2 = MessageDigest.getInstance(algorithm.getValue());
        for (byte[] arr : bytes) {
            ByteHash.hashTimes(algorithm, arr, times).ifPresent(hash::add);
            digest2.update(arr);

            for (int i = 0; i < times - 1; i++) {
                digest2.update(digest2.digest());
            }

            digest.update(digest2.digest());
        }

        Assert.assertArrayEquals(hash.finalizeHash().getResult().get(), digest.digest());

        for (byte[] arr : bytes) {
            hash.add(arr);
        }

        Assert.assertFalse(hash.clear().finalizeHash().getResult().isPresent());
        Assert.assertFalse(hash.finalizeHash().getResult().isPresent());
    }
}
