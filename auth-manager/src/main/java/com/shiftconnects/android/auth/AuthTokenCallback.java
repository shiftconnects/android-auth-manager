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

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerCallback;
import android.accounts.AccountManagerFuture;
import android.accounts.AuthenticatorException;
import android.accounts.OperationCanceledException;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;

import java.io.IOException;

/**
 * Callback required for AccountManager which returns after a call to
 * {@link android.accounts.AccountManager#getAuthTokenByFeatures(String, String, String[], android.app.Activity, android.os.Bundle, android.os.Bundle, android.accounts.AccountManagerCallback, android.os.Handler)}
 */
public class AuthTokenCallback implements AccountManagerCallback<Bundle> {
    private static final String TAG = AuthTokenCallback.class.getSimpleName();
    private static final boolean DEBUG = false;

    public static interface Callbacks {
        void onGetAuthTokenCanceled();
        void onGetAuthTokenSuccessful(String authToken);
        void onGetAuthTokenNetworkError();
        void onGetAuthTokenFailed(Exception e);
    }

    private AccountManager mAccountManager;
    private String mAuthTokenType;
    private Callbacks mCallbacks;

    public AuthTokenCallback(AccountManager accountManager, String authTokenType, Callbacks callbacks) {
        mAccountManager = accountManager;
        mAuthTokenType = authTokenType;
        mCallbacks = callbacks;
    }

    @Override public void run(AccountManagerFuture<Bundle> future) {
        try {
            final Bundle result = future.getResult();
            String authToken = result.getString(AccountManager.KEY_AUTHTOKEN);

            // when adding an account it doesn't automatically get the token so try to get it explicitly
            if (TextUtils.isEmpty(authToken)) {
                authToken = getAuthTokenFromAccountManager(result.getString(AccountManager.KEY_ACCOUNT_NAME), result.getString(AccountManager.KEY_ACCOUNT_TYPE), mAuthTokenType);
            }
            if (!TextUtils.isEmpty(authToken)) {
                if (DEBUG) {
                    Log.d(TAG, "Successfully retrieved an auth token from AccountManager! " + authToken);
                }
                mCallbacks.onGetAuthTokenSuccessful(authToken);
            } else {
                if (DEBUG) {
                    Log.d(TAG, "Received an empty auth token from AccountManager. Authentication failed :(");
                }
                mCallbacks.onGetAuthTokenFailed(new Exception("Received an empty auth token from AccountManager"));
            }
        } catch (OperationCanceledException e) {
            if (DEBUG) {
                Log.d(TAG, "Authentication was canceled.");
            }
            mCallbacks.onGetAuthTokenCanceled();
        } catch (IOException e) {
            if (DEBUG) {
                Log.d(TAG, "Encountered a network error while trying to authenticate!");
            }
            mCallbacks.onGetAuthTokenNetworkError();
        } catch (AuthenticatorException e) {
            if (DEBUG) {
                Log.d(TAG, "Encountered a generic exception while trying to authenticate!");
            }
            mCallbacks.onGetAuthTokenFailed(e);
        }
    }

    private String getAuthTokenFromAccountManager(String accountName, String accountType, String authTokenType) {
        final Account[] accounts = mAccountManager.getAccountsByType(accountType);
        Account account = null;
        for (Account a : accounts) {
            if (TextUtils.equals(accountName, a.name)) {
                account = a;
            }
        }
        if (account != null) {
            return mAccountManager.peekAuthToken(account, authTokenType);
        }
        return null;
    }
}
