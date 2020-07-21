package mj.crypto.hash;

import mj.crypto.enums.HashAlgorithm;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

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
public class StringHashTest {

    private final List<String> strings = Arrays.asList(
            "",
            "This sentence is for hashing",
            "This is my sample hashing",
            "This is a unit testing class"
    );

    private HashAlgorithm algorithm;

    public StringHashTest(HashAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    @Parameterized.Parameters
    public static Object[] data() {
        return HashAlgorithm.values();
    }

    @Test
    public void hashStringTest() {
        final String string = strings.get(1);
        final int length = string.length();

        Assert.assertTrue(StringHash.hash(algorithm, string).isPresent());
        Assert.assertTrue(StringHash.hash(algorithm, string, length - 6).isPresent());
        Assert.assertTrue(StringHash.hash(algorithm, string, length - 6, length).isPresent());
        Assert.assertTrue(StringHash.hash(algorithm, string, length).isPresent());
        Assert.assertTrue(StringHash.hash(algorithm, string, length, length).isPresent());

        Class<StringIndexOutOfBoundsException> clz = StringIndexOutOfBoundsException.class;
        Assert.assertThrows(clz, () -> StringHash.hash(algorithm, string, length + 1));
        Assert.assertThrows(clz, () -> StringHash.hash(algorithm, string, length, length + 1));
        Assert.assertThrows(clz, () -> StringHash.hash(algorithm, string, length - 5, length + 7));
    }

    @Test
    public void hashNullStringTest() {
        Class<NullPointerException> clz = NullPointerException.class;
        Assert.assertThrows(clz, () -> StringHash.hash(algorithm, null));
        Assert.assertThrows(clz, () -> StringHash.hash(algorithm, null, 0));
        Assert.assertThrows(clz, () -> StringHash.hash(algorithm, null, 0, 1));

    }

    @Test
    public void hashNullStringMoreTimesTest() {
        Class<NullPointerException> clz = NullPointerException.class;
        Assert.assertThrows(clz, () -> StringHash.hashTimes(algorithm, null, 5));
        Assert.assertThrows(clz, () -> StringHash.hashTimes(algorithm, null, 0, 5));
        Assert.assertThrows(clz, () -> StringHash.hashTimes(algorithm, null, 0, 1, 5));
    }

    @Test
    public void hashWithoutPassingValueTest() throws NoSuchAlgorithmException {
        StringHash hash = new StringHash(algorithm);
        Assert.assertFalse(hash.finalizeHash().getResult().isPresent());
        Assert.assertFalse(hash.finalizeHash(5).getResult().isPresent());
    }

    @Test
    public void hashWithPassingValueMoreTimesTest() throws NoSuchAlgorithmException {
        StringHash hash = new StringHash(algorithm);
        Assert.assertTrue(hash.add("").finalizeHash().getResult().isPresent());
        Assert.assertTrue(hash.add("").finalizeHash(5).getResult().isPresent());
    }

    @Test
    public void hashEmptyStringTest() {
        Assert.assertTrue(StringHash.hash(algorithm, "").isPresent());
        Assert.assertTrue(StringHash.hash(algorithm, "", 0).isPresent());
        Assert.assertTrue(StringHash.hash(algorithm, "", 0, 0).isPresent());

        Class<StringIndexOutOfBoundsException> clz = StringIndexOutOfBoundsException.class;
        Assert.assertThrows(clz, () -> StringHash.hash(algorithm, "", -1));
        Assert.assertThrows(clz, () -> StringHash.hash(algorithm, "", -1, 0));
        Assert.assertThrows(clz, () -> StringHash.hash(algorithm, "", 0, 1));
        Assert.assertThrows(clz, () -> StringHash.hash(algorithm, "", 1));
        Assert.assertThrows(clz, () -> StringHash.hash(algorithm, "", 1, 1));
    }

    @Test
    public void hashEmptyStringMoreTimesTest() {
        Assert.assertTrue(StringHash.hashTimes(algorithm, "", -1).isPresent());
        Assert.assertTrue(StringHash.hashTimes(algorithm, "", 0).isPresent());
        Assert.assertTrue(StringHash.hashTimes(algorithm, "", 4).isPresent());
        Assert.assertTrue(StringHash.hashTimes(algorithm, "", 0, 4).isPresent());
        Assert.assertTrue(StringHash.hashTimes(algorithm, "", 0, 0, -2).isPresent());
        Assert.assertTrue(StringHash.hashTimes(algorithm, "", 0, 0, 1000).isPresent());
    }

    @Test
    public void hashStringAndCheckResultTest() throws NoSuchAlgorithmException {
        final String string = strings.get(1);
        final int length = string.length();

        MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());

        Assert.assertArrayEquals(
                StringHash.hash(algorithm, string).get(),
                digest.digest(string.getBytes())
        );

        Assert.assertArrayEquals(
                StringHash.hash(algorithm, string, length - 2).get(),
                digest.digest(string.substring(length - 2).getBytes())
        );

        Assert.assertArrayEquals(
                StringHash.hash(algorithm, string, length - 2, length - 1).get(),
                digest.digest(string.substring(length - 2, length - 1).getBytes())
        );
    }

    @Test
    public void hashListOfStringAndCheckResultTest() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());
        StringHash hash = new StringHash(algorithm);

        for (String string : strings) {
            hash.add(string);
            digest.update(string.getBytes());
        }

        Assert.assertArrayEquals(hash.finalizeHash().getResult().get(), digest.digest());

        for (String string : strings) {
            hash.add(string, string.length() / 2);
            digest.update(string.substring(string.length() / 2).getBytes());
        }

        Assert.assertArrayEquals(hash.finalizeHash().getResult().get(), digest.digest());

        for (String string : strings) {
            int length = string.length();
            int from = length != 0 ? length / 2 : length;
            int to = length != 0 ? length / 2 + 1 : length;
            hash.add(string, from, to);
            digest.update(string.substring(from, to).getBytes());
        }

        Assert.assertArrayEquals(hash.finalizeHash().getResult().get(), digest.digest());

        for (String string : strings) {
            int length = string.length();
            int from = length != 0 ? length / 2 : length;
            int to = length != 0 ? length / 2 + 1 : length;
            hash.add(string, from, to);
        }

        Assert.assertFalse(hash.clear().finalizeHash().getResult().isPresent());
        Assert.assertFalse(hash.finalizeHash().getResult().isPresent());
    }
}
