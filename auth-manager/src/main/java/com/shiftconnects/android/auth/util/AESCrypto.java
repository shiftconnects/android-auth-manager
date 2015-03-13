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

package com.shiftconnects.android.auth.util;

import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

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

import static com.shiftconnects.android.auth.util.AuthConstants.DEBUG;
import static com.shiftconnects.android.auth.util.AuthConstants.DEBUG_TAG;

/**
 * Crypto implementation using an AES transformation with a 128-bit key length.
 */
public class AESCrypto implements Crypto {

    private static final String TAG = AESCrypto.class.getSimpleName();
    private static final String IV = "iv";
    private static final String SALT = "salt";

    private static final int ITERATIONS = 1000;
    private static final int KEY_LENGTH = 128;
    private static final int SALT_LENGTH = 128; // same size as key output

    private SharedPreferences mSharedPrefs;
    private byte[] mSalt;
    private byte[] mIv;

    /**
     * Default constructor
     * @param sharedPrefs - {@link SharedPreferences} used to store a generated salt and iv used for
     *                    encryption/decryption
     */
    public AESCrypto(SharedPreferences sharedPrefs) {
        mSharedPrefs = sharedPrefs;
        mSalt = generateSalt();
        mIv = generateIV();
    }

    @NonNull
    public String encrypt(@NonNull String password, @NonNull String decryptedString) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = new IvParameterSpec(mIv);
        cipher.init(Cipher.ENCRYPT_MODE, deriveKeyPbkdf2(mSalt, password), ivParams);
        byte[] cipherBytes = cipher.doFinal(decryptedString.getBytes("UTF-8"));
        return Base64.encodeToString(cipherBytes, Base64.DEFAULT);
    }

    @NonNull
    public String decrypt(@NonNull String password, @NonNull String encryptedString) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = new IvParameterSpec(mIv);
        cipher.init(Cipher.DECRYPT_MODE, deriveKeyPbkdf2(mSalt, password), ivParams);
        byte[] plaintext = cipher.doFinal(Base64.decode(encryptedString, Base64.DEFAULT));
        return new String(plaintext , "UTF-8");
    }

    private SecretKey deriveKeyPbkdf2(byte[] salt, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private byte[] generateSalt() {
        byte[] salt;
        String saltString = mSharedPrefs.getString(SALT, null);
        if (TextUtils.isEmpty(saltString)) {
            try {
                if (DEBUG) {
                    Log.d(String.format(DEBUG_TAG, TAG), "salt is null. Generating one...");
                }

                // generate a new salt
                SecureRandom secureRandom = new SecureRandom();
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(SALT_LENGTH, secureRandom);
                SecretKey key = keyGenerator.generateKey();
                salt = key.getEncoded();

                // encode it
                saltString = Base64.encodeToString(salt, Base64.DEFAULT);

                if (DEBUG) {
                    Log.d(String.format(DEBUG_TAG, TAG), "Newly generated encoded salt: " + saltString);
                }

                // save to shared prefs
                mSharedPrefs.edit().putString(SALT, saltString).apply();
            } catch (NoSuchAlgorithmException e) {
                Log.e(String.format(DEBUG_TAG, TAG), "Could not setup salt. This is bad.");
                throw new RuntimeException("Unable to setup salt. Cannot run app.", e);
            }
        } else {
            salt = Base64.decode(saltString, Base64.DEFAULT);

            if (DEBUG) {
                Log.d(String.format(DEBUG_TAG, TAG), "Salt loaded from disk: " + saltString);
            }
        }
        return salt;
    }

    private byte[] generateIV() {
        byte[] iv;
        String ivString = mSharedPrefs.getString(IV, null);
        if (TextUtils.isEmpty(ivString)) {
            try {
                if (DEBUG) {
                    Log.d(String.format(DEBUG_TAG, TAG), "Initialization vector is null. Generating one...");
                }

                // generate a new iv
                SecureRandom secureRandom = new SecureRandom();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                iv = new byte[cipher.getBlockSize()];
                secureRandom.nextBytes(iv);

                // encode it
                ivString = Base64.encodeToString(iv, Base64.DEFAULT);

                if (DEBUG) {
                    Log.d(String.format(DEBUG_TAG, TAG), "Newly generated encoded initialization vector: " + ivString);
                }

                // save to shared prefs
                mSharedPrefs.edit().putString(IV, ivString).apply();
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                Log.e(String.format(DEBUG_TAG, TAG), "Could not setup IV. This is bad.");
                throw new RuntimeException("Unable to setup IV. Cannot run app.", e);
            }
        } else {
            iv = Base64.decode(ivString, Base64.DEFAULT);

            if (DEBUG) {
                Log.d(String.format(DEBUG_TAG, TAG), "IV loaded from disk: " + ivString);
            }
        }
        return iv;
    }
}
