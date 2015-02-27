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

package com.shiftconnects.android.auth;

import android.accounts.AccountManager;

/**
 * Interface that an Activity being used to authenticate must implement
 */
public interface AuthenticatorActivity {
    public static final String KEY_ACCOUNT_TYPE = AccountManager.KEY_ACCOUNT_TYPE;
    public static final String KEY_ACCOUNT_NAME = AccountManager.KEY_ACCOUNT_NAME;
    public static final String KEY_AUTHTOKEN = AccountManager.KEY_AUTHTOKEN;
    public static final String KEY_AUTHTOKEN_TYPE = "authTokenType";
    public static final String KEY_NEW_ACCOUNT = "newAccount";
}
