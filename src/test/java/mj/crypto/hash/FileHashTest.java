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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 03-07-2020
 */

@RunWith(Parameterized.class)
public class FileHashTest {

    @ClassRule
    public static final TemporaryFolder tmpDir = new TemporaryFolder();
    private static final List<File> files = new ArrayList<>();
    @Parameterized.Parameter
    public HashAlgorithm algorithm;

    @Parameterized.Parameters
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
                    writer.append("FileHash").append('\n');
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
    public void hashNullFileTest() {
        Class<? extends Exception> clz = NullPointerException.class;
        Assert.assertThrows(clz, () -> FileHash.hash(algorithm, null));
        Assert.assertThrows(clz, () -> FileHash.hashTimes(algorithm, null, 3));
    }

    @Test
    public void hashWithoutPassingValueTest() throws NoSuchAlgorithmException {
        FileHash hash = new FileHash(algorithm);
        Assert.assertFalse(hash.finalizeHash().getResult().isPresent());
        Assert.assertFalse(hash.finalizeHash(5).getResult().isPresent());
    }

    @Test
    public void hashWithPassingValueMoreTimesTest() throws NoSuchAlgorithmException {
        FileHash hash = new FileHash(algorithm);

        File empty = files.get(0);
        Assert.assertTrue(hash.add(empty).finalizeHash().getResult().isPresent());
        Assert.assertTrue(hash.add(empty).finalizeHash(5).getResult().isPresent());
    }

    @Test
    public void hashEmptyFileTest() {
        File emptyFile = files.get(0);
        Assert.assertTrue(FileHash.hash(algorithm, emptyFile).isPresent());
        Assert.assertTrue(FileHash.hashTimes(algorithm, emptyFile, 5).isPresent());
    }

    @Test
    public void hashFileTest() {
        File file = files.get(1);
        Assert.assertTrue(FileHash.hash(algorithm, file).isPresent());
        Assert.assertTrue(FileHash.hashTimes(algorithm, file, -1).isPresent());
        Assert.assertTrue(FileHash.hashTimes(algorithm, file, 2).isPresent());
    }

    @Test
    public void hashFileAndCheckResultTest() throws NoSuchAlgorithmException, IOException {
        File file = files.get(1);

        FileInputStream stream = new FileInputStream(file);
        MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());

        int read;
        while ((read = stream.read()) != -1) {
            digest.update((byte) read);
        }
        stream.close();

        FileHash.hash(algorithm, file).ifPresent(hash -> Assert.assertArrayEquals(hash, digest.digest()));

        stream = new FileInputStream(file);
        while ((read = stream.read()) != -1) {
            digest.update((byte) read);
        }
        stream.close();

        int times = 2;
        for (int i = 0; i < times - 1; i++) {
            digest.update(digest.digest());
        }

        new FileHash(algorithm)
                .add(file)
                .finalizeHash(times)
                .getResult()
                .ifPresent(hash -> Assert.assertArrayEquals(hash, digest.digest()));
    }

    @Test
    public void hashListOfFilesAndCheckResultTest() throws NoSuchAlgorithmException, IOException {
        FileHash hash = new FileHash(algorithm);
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
            hash.add(file);
        }

        Assert.assertArrayEquals(hash.finalizeHash().getResult().get(), digest.digest());

        for (File file : files) {
            try (FileInputStream stream = new FileInputStream(file)) {
                int read;
                while ((read = stream.read()) != -1) {
                    digest2.update((byte) read);
                }
            }

            digest.update(digest2.digest());
            hash.add(file);
        }

        int times = 3;
        for (int i = 0; i < times - 2; i++) {
            digest.update(digest.digest());
        }

        Assert.assertArrayEquals(hash.finalizeHash(times).getResult().get(), digest.digest());
    }

    @Test
    public void hashListOfFilesAndResetTheDigestAndCheckTheResultTest() throws NoSuchAlgorithmException {
        FileHash hash = new FileHash(algorithm);

        for (File file : files) {
            hash.add(file);
        }

        Assert.assertFalse(hash.clear().finalizeHash().getResult().isPresent());
    }
}
