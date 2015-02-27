/*
 * Copyright (C) 2015 P100 OG, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.shiftconnects.android.auth.example.util;

import android.util.Base64;

import com.shiftconnects.android.auth.util.Crypto;

import org.jetbrains.annotations.NotNull;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class ExampleCrypto implements Crypto {
    private static final int ITERATIONS = 1000;
    private static final int KEY_LENGTH = 128;
    private static final int SALT_LENGTH = 128; // same size as key output

    private byte[] mSalt;
    private byte[] mIv;

    public ExampleCrypto(byte[] salt, byte[] initializationVector) {
        mSalt = salt;
        mIv = initializationVector;
    }

    @NotNull
    public String encrypt(@NotNull String password, @NotNull String decryptedString) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = new IvParameterSpec(mIv);
        cipher.init(Cipher.ENCRYPT_MODE, deriveKeyPbkdf2(mSalt, password), ivParams);
        byte[] cipherBytes = cipher.doFinal(decryptedString.getBytes("UTF-8"));
        return Base64.encodeToString(cipherBytes, Base64.DEFAULT);
    }

    @NotNull
    public String decrypt(@NotNull String password, @NotNull String encryptedString) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = new IvParameterSpec(mIv);
        cipher.init(Cipher.DECRYPT_MODE, deriveKeyPbkdf2(mSalt, password), ivParams);
        byte[] plaintext = cipher.doFinal(Base64.decode(encryptedString, Base64.DEFAULT));
        return new String(plaintext , "UTF-8");
    }

    private static SecretKey deriveKeyPbkdf2(byte[] salt, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    @NotNull
    public static byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(SALT_LENGTH, secureRandom);
        SecretKey key = keyGenerator.generateKey();
        return key.getEncoded();
    }

    @NotNull
    public static byte[] generateIV() throws NoSuchPaddingException, NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        secureRandom.nextBytes(iv);
        return iv;
    }
}
