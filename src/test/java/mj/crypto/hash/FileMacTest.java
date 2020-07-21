package mj.crypto.hash;

import mj.crypto.enums.KeyAlgorithm;
import mj.crypto.enums.MacAlgorithm;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 05-07-2020
 */

@RunWith(Parameterized.class)
public class FileMacTest {

    @ClassRule
    public static final TemporaryFolder tmpDir = new TemporaryFolder();
    private static final List<File> files = new ArrayList<>();
    private static SecretKey key;

    @Parameterized.Parameter
    public MacAlgorithm algorithm;

    @Parameterized.Parameters
    public static MacAlgorithm[] data() {
        return MacAlgorithm.values();
    }

    @BeforeClass
    public static void generateKey() throws NoSuchAlgorithmException {
        FileMacTest.key = KeyGenerator.getInstance(KeyAlgorithm.DES.getValue()).generateKey();
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
    public void macNullFileTest() {
        Class<? extends Exception> clz = IllegalArgumentException.class;
        Assert.assertThrows(clz, () -> FileMac.mac(algorithm, key, null));
        Assert.assertThrows(clz, () -> FileMac.macTimes(algorithm, key, null, 3));
    }

    @Test
    public void hashWithoutPassingValueTest() throws NoSuchAlgorithmException, InvalidKeyException {
        FileMac mac = new FileMac(algorithm, key);
        Assert.assertFalse(mac.finalizeMac().getResult().isPresent());
        Assert.assertFalse(mac.finalizeMac(5).getResult().isPresent());
    }

    @Test
    public void hashWithPassingValueMoreTimesTest() throws NoSuchAlgorithmException, InvalidKeyException {
        FileMac mac = new FileMac(algorithm, key);

        File empty = files.get(0);
        Assert.assertTrue(mac.add(empty).finalizeMac().getResult().isPresent());
        Assert.assertTrue(mac.add(empty).finalizeMac(5).getResult().isPresent());
    }

    @Test
    public void hashEmptyFileTest() {
        File emptyFile = files.get(0);
        Assert.assertTrue(FileMac.mac(algorithm, key, emptyFile).isPresent());
        Assert.assertTrue(FileMac.macTimes(algorithm, key, emptyFile, 5).isPresent());
    }

    @Test
    public void hashFileTest() {
        File file = files.get(1);
        Assert.assertTrue(FileMac.mac(algorithm, key, file).isPresent());
        Assert.assertTrue(FileMac.macTimes(algorithm, key, file, -1).isPresent());
        Assert.assertTrue(FileMac.macTimes(algorithm, key, file, 2).isPresent());
    }

    @Test
    public void hashFileAndCheckResultTest() throws NoSuchAlgorithmException, IOException, InvalidKeyException {
        File file = files.get(1);

        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(key);

        try (InputStream stream = new FileInputStream(file)) {
            int read;
            while ((read = stream.read()) != -1) {
                mac.update((byte) read);
            }
        }

        FileMac.mac(algorithm, key, file).ifPresent(hash -> Assert.assertArrayEquals(hash, mac.doFinal()));

        try (InputStream stream = new FileInputStream(file)) {
            int read;
            while ((read = stream.read()) != -1) {
                mac.update((byte) read);
            }
        }

        int times = 2;
        for (int i = 0; i < times - 1; i++) {
            mac.update(mac.doFinal());
        }

        new FileMac(algorithm, key)
                .add(file)
                .finalizeMac(times)
                .getResult()
                .ifPresent(hash -> Assert.assertArrayEquals(hash, mac.doFinal()));
    }

    @Test
    public void hashListOfFilesAndCheckResultTest() throws NoSuchAlgorithmException, IOException, InvalidKeyException {
        FileMac fileMac = new FileMac(algorithm, key);

        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(key);
        Mac mac2 = Mac.getInstance(algorithm.getValue());
        mac2.init(key);

        for (File file : files) {
            try (FileInputStream stream = new FileInputStream(file)) {
                int read;
                while ((read = stream.read()) != -1) {
                    mac2.update((byte) read);
                }
            }

            mac.update(mac2.doFinal());
            fileMac.add(file);
        }

        Assert.assertArrayEquals(fileMac.finalizeMac().getResult().get(), mac.doFinal());

        for (File file : files) {
            try (FileInputStream stream = new FileInputStream(file)) {
                int read;
                while ((read = stream.read()) != -1) {
                    mac2.update((byte) read);
                }
            }

            mac.update(mac2.doFinal());
            fileMac.add(file);
        }

        int times = 3;
        for (int i = 0; i < times - 2; i++) {
            mac.update(mac.doFinal());
        }

        Assert.assertArrayEquals(fileMac.finalizeMac(times).getResult().get(), mac.doFinal());
    }

    @Test
    public void hashListOfFilesAndResetTheDigestAndCheckTheResultTest() throws NoSuchAlgorithmException, InvalidKeyException {
        FileMac hash = new FileMac(algorithm, key);

        for (File file : files) {
            hash.add(file);
        }

        Assert.assertFalse(hash.clear().finalizeMac().getResult().isPresent());
        Assert.assertFalse(hash.finalizeMac().getResult().isPresent());
    }
}
