package com.ayra.karan.cipher;

/**
 * The Caeser cipher is monoalphabetic substitution cipher which rotates through the letters of the alphabet.
 *
 * Each letter is encrypted (or decrypted) one at a time, by moving it forwards (or backwards) in the alphabet by the
 * number of positions indicated by the key. This wraps around from Z back to A (or from A back to Z for decryption).
 *
 * Examples:
 *
 * encrypt("ABC", 2) -> "CDE"
 * encrypt("XYZ", 2) -> "ZAB"
 * decrypt("TUFG", 1) -> "STEF"
 * decrypt("CD", 3) -> "ZA"
 *
 * This cipher provides almost no security, as it produces patterns in the ciphertext, and frequency analysis could be
 * used to guess the key. Additionally, an attacker could simply just try all 25 possible keys.
 *
 * @author Stefan Petrucev
 */
public interface CaesarCipher {

    /**
     * Decrypt the given ciphertext using the Caesar cipher with the given key.
     *
     * @param ciphertext ciphertext to decrypt, which must contain only uppercase letters A to Z
     * @param key key to use, which must be between 0 and 25
     * @return resulting plaintext from decryption
     * @throws IllegalArgumentException when {@code ciphertext} contains anything other than uppercase A to Z
     * @throws IllegalArgumentException when {@code key} is less than 0 or greater than 25
     * @see #encrypt
     */
    String decrypt(String ciphertext, int key);

    /**
     * Encrypt the given plaintext using the Caesar cipher with the given key.
     *
     * @param plaintext plaintext to decrypt, which must contain only uppercase letters A to Z
     * @param key key to use, which must be between 0 and 25
     * @return resulting ciphertext from decryption
     * @throws IllegalArgumentException when {@code plaintext} contains anything other than uppercase A to Z
     * @throws IllegalArgumentException when {@code key} is less than 0 or greater than 25
     * @see #decrypt
     */
    String encrypt(String plaintext, int key);
}
