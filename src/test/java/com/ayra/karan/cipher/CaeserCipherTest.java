package com.ayra.karan.cipher;

import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

public class CaeserCipherTest {

    private static final String CIPHERTEXT = "EFGHIJKLMNOPQRSTUVWXYZABCD";
    private static final int KEY = 4;
    private static final String PLAINTEXT = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private CaesarCipher ciper = new CaesarCipherImpl();

    @Test
    public void testDecrypt() {
        String ciphertext = ciper.decrypt("B", 1);

        assertThat("Ciphertext should not be null", ciphertext, notNullValue());
        assertThat("Ciphertext should be " + "A", ciphertext, is("A"));
    }

    @Test
    public void testDecryptAlphabet() {
        String plaintext = ciper.decrypt(CIPHERTEXT, KEY);

        assertThat("Plaintext should not be null", plaintext, notNullValue());
        assertThat("Plaintext should be " + PLAINTEXT, plaintext, is(PLAINTEXT));
    }

    @Test
    public void testDecryptWithCiphertextBlank() {
        String plaintext = ciper.decrypt("", KEY);

        assertThat("Plaintext should not be null", plaintext, notNullValue());
        assertThat("Plaintext should be blank", plaintext, is(""));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptWithCipertextInvalid() {
        ciper.decrypt("INVALID-123!", KEY);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptWithKeyInvalid() {
        ciper.decrypt(CIPHERTEXT, 26);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptWithKeyNegative() {
        ciper.decrypt(CIPHERTEXT, -1);
    }

    @Test
    public void testDecryptWithKeyZero() {
        String plaintext = ciper.decrypt(CIPHERTEXT, 0);

        assertThat("Plaintext should not be null", plaintext, notNullValue());
        assertThat("Plaintext should be the same as ciphertext " + CIPHERTEXT, plaintext, is(CIPHERTEXT));
    }

    @Test
    public void testEncrypt() {
        String ciphertext = ciper.encrypt("A", 1);

        assertThat("Ciphertext should not be null", ciphertext, notNullValue());
        assertThat("Ciphertext should be " + "B", ciphertext, is("B"));
    }

    @Test
    public void testEncryptAlphabet() {
        String ciphertext = ciper.encrypt(PLAINTEXT, KEY);

        assertThat("Ciphertext should not be null", ciphertext, notNullValue());
        assertThat("Ciphertext should be " + CIPHERTEXT, ciphertext, is(CIPHERTEXT));
    }

    @Test
    public void testEncryptWithPlaintextBlank() {
        String ciphertext = ciper.encrypt("", KEY);

        assertThat("Ciphertext should not be null", ciphertext, notNullValue());
        assertThat("Ciphertext should not be blank", ciphertext, is(""));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptWithdPlaintextInvalid() {
        ciper.encrypt("INVALID-123!", KEY);
    }


    @Test(expected = IllegalArgumentException.class)
    public void testEncryptWithdKeyInvalid() {
        ciper.encrypt(PLAINTEXT, 26);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptWithKeyNegative() {
        ciper.encrypt(PLAINTEXT, -1);
    }

    @Test
    public void testEncryptWithKeyZero() {
        String ciphertext = ciper.encrypt(PLAINTEXT, 0);

        assertThat("Ciphertext should not be null", ciphertext, notNullValue());
        assertThat("Ciphertexy should be the same as plaintext " + PLAINTEXT, ciphertext, is(PLAINTEXT));
    }
}
