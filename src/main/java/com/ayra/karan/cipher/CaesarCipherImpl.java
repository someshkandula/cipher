package com.ayra.karan.cipher;

import static java.util.Objects.requireNonNull;

public class CaesarCipherImpl implements CaesarCipher {

    private static final int CODEPOINT_OF_CAPITAL_A = "A".codePointAt(0);
    private static final int SIZE_OF_ALPHABET = 26;

    @Override
    public String decrypt(String ciphertext, int key) {
        validateInput(ciphertext);
        validateKey(key);

        return applyCipher(ciphertext, -key);
    }

    @Override
    public String encrypt(String plaintext, int key) {
        validateInput(plaintext);
        validateKey(key);

        return applyCipher(plaintext, key);
    }

    private String applyCipher(String input, int key) {
        return input
                .chars()
                .map(i -> i - CODEPOINT_OF_CAPITAL_A)                   // zero the character
                .map(i ->  i + key)                                     // apply the key to the character
                .map(i -> (i + SIZE_OF_ALPHABET) % SIZE_OF_ALPHABET)    // adjust for wrapping
                .map(i -> i + CODEPOINT_OF_CAPITAL_A)                   // reverse zeroing the character
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }

    private void validateKey(int key) {
        if (key < 0) {
            throw new IllegalArgumentException("Invalid key: " + key
                    + "; key too small. Key must be between 0 and 25, inclusive.");
        }
        if (key > SIZE_OF_ALPHABET-1) {
            throw new IllegalArgumentException("Invalid key: " + key
                    + "; key too large. Key must be between 0 and 25, inclusive.");
        }
    }

    private void validateInput(String input) {
        requireNonNull(input, "input");

        if (!input.matches("[A-Z]*")) {
            throw new IllegalArgumentException("Invalid input " + input
                    + ". Input can only contain uppercase letters A to Z");
        }
    }
}
