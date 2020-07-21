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
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 05-07-2020
 */

@RunWith(Parameterized.class)
public class InputStreamMacTest {

    @ClassRule
    public static final TemporaryFolder tmpDir = new TemporaryFolder();
    private static final List<File> files = new ArrayList<>();
    private static SecretKey key;

    @Parameter
    public MacAlgorithm algorithm;

    @Parameters
    public static MacAlgorithm[] data() {
        return MacAlgorithm.values();
    }

    @BeforeClass
    public static void generateKey() throws NoSuchAlgorithmException {
        InputStreamMacTest.key = KeyGenerator.getInstance(KeyAlgorithm.DES.getValue()).generateKey();
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
        Class<? extends Exception> clz = IllegalArgumentException.class;
        Assert.assertThrows(clz, () -> InputStreamMac.mac(algorithm, key, null));
        Assert.assertThrows(clz, () -> InputStreamMac.macTimes(algorithm, key, null, 3));
    }

    @Test
    public void hashEmptyInputStreamTest() {
        InputStream stream = new ByteArrayInputStream(new byte[0]);
        Assert.assertTrue(InputStreamMac.mac(algorithm, key, stream).isPresent());
        Assert.assertTrue(InputStreamMac.macTimes(algorithm, key, stream, 5).isPresent());
    }

    @Test
    public void hashWithoutPassingValueTest() throws NoSuchAlgorithmException, InvalidKeyException {
        InputStreamMac mac = new InputStreamMac(algorithm, key);
        Assert.assertFalse(mac.finalizeMac().getResult().isPresent());
        Assert.assertFalse(mac.finalizeMac(5).getResult().isPresent());
    }

    @Test
    public void hashWithPassingValueMoreTimesTest() throws NoSuchAlgorithmException, FileNotFoundException, InvalidKeyException {
        InputStreamMac mac = new InputStreamMac(algorithm, key);

        File empty = files.get(0);
        Assert.assertTrue(mac.add(new FileInputStream(empty)).finalizeMac().getResult().isPresent());
        Assert.assertTrue(mac.add(new FileInputStream(empty)).finalizeMac(5).getResult().isPresent());
    }

    @Test
    public void hashInputStreamTest() throws FileNotFoundException {
        File file = files.get(1);
        Assert.assertTrue(InputStreamMac.mac(algorithm, key, new FileInputStream(file)).isPresent());
        Assert.assertTrue(InputStreamMac.macTimes(algorithm, key, new FileInputStream(file), -1).isPresent());
        Assert.assertTrue(InputStreamMac.macTimes(algorithm, key, new FileInputStream(file), 2).isPresent());
    }

    @Test
    public void hashInputStreamAndCheckResultTest() throws NoSuchAlgorithmException, IOException, InvalidKeyException {
        File file = files.get(1);

        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(key);

        try (InputStream stream = new FileInputStream(file)) {
            int read;
            while ((read = stream.read()) != -1) {
                mac.update((byte) read);
            }
        }

        Optional<byte[]> opMac = InputStreamMac.mac(algorithm, key, new FileInputStream(file));
        opMac.ifPresent(result -> Assert.assertArrayEquals(result, mac.doFinal()));

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

        new InputStreamMac(algorithm, key)
                .add(new FileInputStream(file))
                .finalizeMac(times)
                .getResult()
                .ifPresent(result -> Assert.assertArrayEquals(result, mac.doFinal()));
    }

    @Test
    public void hashListOfInputStreamsAndCheckResultTest() throws NoSuchAlgorithmException, IOException, InvalidKeyException {
        InputStreamMac streamMac = new InputStreamMac(algorithm, key);

        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(key);
        Mac mac2 = Mac.getInstance(algorithm.getValue());
        mac2.init(key);

        for (File file : files) {
            try (InputStream stream = new FileInputStream(file)) {
                int read;
                while ((read = stream.read()) != -1) {
                    mac2.update((byte) read);
                }
            }

            mac.update(mac2.doFinal());
            streamMac.add(new FileInputStream(file));
        }

        streamMac.finalizeMac().getResult().ifPresent(result -> Assert.assertArrayEquals(result, mac.doFinal()));

        for (File file : files) {
            try (InputStream stream = new FileInputStream(file)) {
                int read;
                while ((read = stream.read()) != -1) {
                    mac2.update((byte) read);
                }
            }

            mac.update(mac2.doFinal());
            streamMac.add(new FileInputStream(file));
        }

        int times = 3;
        for (int i = 0; i < times - 2; i++) {
            mac.update(mac.doFinal());
        }

        streamMac.finalizeMac(times).getResult().ifPresent(result -> Assert.assertArrayEquals(result, mac.doFinal()));
    }

    @Test
    public void hashListOfFilesAndResetTheDigestAndCheckTheResultTest() throws NoSuchAlgorithmException, IOException, InvalidKeyException {
        InputStreamMac mac = new InputStreamMac(algorithm, key);

        for (File file : files) {
            mac.add(new FileInputStream(file));
        }

        Assert.assertFalse(mac.clear().finalizeMac().getResult().isPresent());
    }
}
