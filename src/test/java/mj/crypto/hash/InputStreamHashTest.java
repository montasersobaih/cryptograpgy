package mj.crypto.hash;

import mj.crypto.enums.HashAlgorithm;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 03-07-2020
 */

@RunWith(Parameterized.class)
public class InputStreamHashTest {

    @ClassRule
    public static final TemporaryFolder tmpDir = new TemporaryFolder();
    private static final List<File> files = new ArrayList<>();
    @Parameter
    public HashAlgorithm algorithm;

    @Parameters
    public static HashAlgorithm[] data() {
        return HashAlgorithm.values();
    }

    @BeforeClass
    public static void initFiles() throws IOException {
        tmpDir.newFolder("Test Folder");
        for (int i = 0; i <= 2; i++) {
            File file = tmpDir.newFile(String.format("TestFile%d.txt", i + 1));

            FileWriter writer = new FileWriter(file);
            switch (i) {
                case 1:
                    writer.append("This sentence is for hashing").append('\n');
                    writer.append("This is my sample hashing").append('\n');
                    writer.append("This is a unit testing class").append('\n');
                    break;
                case 2:
                    writer.append("Hash").append('\n');
                    writer.append("AbstractHash").append('\n');
                    writer.append("InputStreamHash").append('\n');
                    break;
            }
            writer.close();

            files.add(file);
        }
    }

    @AfterClass
    public static void destroyFiles() {
        tmpDir.delete();
    }

    @Test
    public void hashNullInputStreamTest() {
        Class<? extends Exception> clz = NullPointerException.class;
        Assert.assertThrows(clz, () -> InputStreamHash.hash(algorithm, null));
        Assert.assertThrows(clz, () -> InputStreamHash.hashTimes(algorithm, null, 3));
    }

    @Test
    public void hashEmptyInputStreamTest() {
        InputStream stream = new ByteArrayInputStream(new byte[0]);
        Assert.assertTrue(InputStreamHash.hash(algorithm, stream).isPresent());
        Assert.assertTrue(InputStreamHash.hashTimes(algorithm, stream, 5).isPresent());
    }

    @Test
    public void hashWithoutPassingValueTest() throws NoSuchAlgorithmException {
        InputStreamHash hash = new InputStreamHash(algorithm);
        Assert.assertFalse(hash.finalizeHash().getResult().isPresent());
        Assert.assertFalse(hash.finalizeHash(5).getResult().isPresent());
    }

    @Test
    public void hashWithPassingValueMoreTimesTest() throws NoSuchAlgorithmException, FileNotFoundException {
        InputStreamHash hash = new InputStreamHash(algorithm);

        File empty = files.get(0);
        Assert.assertTrue(hash.add(new FileInputStream(empty)).finalizeHash().getResult().isPresent());
        Assert.assertTrue(hash.add(new FileInputStream(empty)).finalizeHash(5).getResult().isPresent());
    }

    @Test
    public void hashInputStreamTest() throws FileNotFoundException {
        File file = files.get(1);
        Assert.assertTrue(InputStreamHash.hash(algorithm, new FileInputStream(file)).isPresent());
        Assert.assertTrue(InputStreamHash.hashTimes(algorithm, new FileInputStream(file), -1).isPresent());
        Assert.assertTrue(InputStreamHash.hashTimes(algorithm, new FileInputStream(file), 2).isPresent());
    }

    @Test
    public void hashInputStreamAndCheckResultTest() throws NoSuchAlgorithmException, IOException {
        File file = files.get(1);

        FileInputStream stream = new FileInputStream(file);
        MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());

        int read;
        while ((read = stream.read()) != -1) {
            digest.update((byte) read);
        }
        stream.close();

        Optional<byte[]> opHash = InputStreamHash.hash(algorithm, new FileInputStream(file));
        opHash.ifPresent(hash -> Assert.assertArrayEquals(hash, digest.digest()));

        stream = new FileInputStream(file);
        while ((read = stream.read()) != -1) {
            digest.update((byte) read);
        }
        stream.close();

        int times = 2;
        for (int i = 0; i < times - 1; i++) {
            digest.update(digest.digest());
        }

        new InputStreamHash(algorithm)
                .add(new FileInputStream(file))
                .finalizeHash(times)
                .getResult()
                .ifPresent(hash -> Assert.assertArrayEquals(hash, digest.digest()));
    }

    @Test
    public void hashListOfInputStreamsAndCheckResultTest() throws NoSuchAlgorithmException, IOException {
        InputStreamHash hash = new InputStreamHash(algorithm);
        MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());
        MessageDigest digest2 = MessageDigest.getInstance(algorithm.getValue());

        for (File file : files) {
            try (FileInputStream stream = new FileInputStream(file)) {
                int read;
                while ((read = stream.read()) != -1) {
                    digest2.update((byte) read);
                }
            }

            digest.update(digest2.digest());
            hash.add(new FileInputStream(file));
        }

        hash.finalizeHash().getResult().ifPresent(result -> Assert.assertArrayEquals(result, digest.digest()));

        for (File file : files) {
            try (FileInputStream stream = new FileInputStream(file)) {
                int read;
                while ((read = stream.read()) != -1) {
                    digest2.update((byte) read);
                }
            }

            digest.update(digest2.digest());
            hash.add(new FileInputStream(file));
        }

        int times = 3;
        for (int i = 0; i < times - 2; i++) {
            digest.update(digest.digest());
        }

        hash.finalizeHash(times).getResult().ifPresent(result -> Assert.assertArrayEquals(result, digest.digest()));
    }

    @Test
    public void hashListOfFilesAndResetTheDigestAndCheckTheResultTest() throws NoSuchAlgorithmException, IOException {
        InputStreamHash hash = new InputStreamHash(algorithm);

        for (File file : files) {
            hash.add(new FileInputStream(file));
        }

        Assert.assertFalse(hash.clear().finalizeHash().getResult().isPresent());
    }
}
