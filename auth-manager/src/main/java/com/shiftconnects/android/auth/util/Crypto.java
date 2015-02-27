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

import org.jetbrains.annotations.NotNull;

/**
 * Interface to encrypt and decrypt a string.
 */
public interface Crypto {

    /**
     * Encrypt the passed in decrypted string
     * @param password - the password to be used to encrypt the string
     * @param decryptedString - the decrypted string
     * @return the encrypted string
     * @throws Exception
     */
    @NotNull
    public String encrypt(@NotNull String password, @NotNull String decryptedString) throws Exception;

    /**
     * Decrypt the passed in encrypted string
     * @param password - - the password to be used to decrypt the string
     * @param encryptedString - the encrypted string
     * @return the decrypted string
     * @throws Exception
     */
    @NotNull
    public String decrypt(@NotNull String password, @NotNull String encryptedString) throws Exception;

}
