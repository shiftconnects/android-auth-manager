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

/**
 * Constants used with authenticating accounts
 */
public class AuthConstants {

    public static final String KEY_REFRESH_TOKEN = "refreshToken";
    public static final String KEY_TOKEN_EXPIRATION_TIME = "tokenExpirationTime";
    public static final String KEY_IS_CLIENT_CREDENTIALS = "isClientCredentials";
    public static final String VALUE_IS_CLIENT_CREDENTIALS = "true";

    public static boolean DEBUG = false;
    public static final String DEBUG_TAG = "android-auth-manager [%s]";

    public static void setDebug(boolean debug) {
        DEBUG = debug;
    }
}
