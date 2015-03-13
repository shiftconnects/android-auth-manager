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

import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.accounts.NetworkErrorException;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;

import static com.shiftconnects.android.auth.util.AuthConstants.DEBUG;
import static com.shiftconnects.android.auth.util.AuthConstants.DEBUG_TAG;

/**
 * This class handles interfacing with {@link android.accounts.AccountManager} to add accounts and retrieve auth tokens
 */
public class AccountAuthenticator extends AbstractAccountAuthenticator {

    private static final String TAG = AccountAuthenticator.class.getSimpleName();

    private Context mContext;
    private Class mLoginClass;
    private AuthenticationManager mAuthenticationManager;

    public AccountAuthenticator(Context context, Class loginClass, AuthenticationManager authenticationManager) {
        super(context);
        mContext = context;
        mLoginClass = loginClass;
        mAuthenticationManager = authenticationManager;
    }

    @Override
    public Bundle addAccount(AccountAuthenticatorResponse response, String accountType, String authTokenType, String[] requiredFeatures, Bundle options) throws NetworkErrorException {
        final Intent intent = new Intent(mContext, mLoginClass);
        intent.putExtra(AuthenticatorActivity.KEY_ACCOUNT_TYPE, accountType);
        intent.putExtra(AuthenticatorActivity.KEY_AUTHTOKEN_TYPE, authTokenType);
        intent.putExtra(AuthenticatorActivity.KEY_NEW_ACCOUNT, true);
        intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);

        final Bundle bundle = new Bundle();
        bundle.putParcelable(AccountManager.KEY_INTENT, intent);
        return bundle;
    }

    @Override
    public Bundle getAuthToken(AccountAuthenticatorResponse response, Account account, String authTokenType, Bundle options) throws NetworkErrorException {
        if (DEBUG) {
            Log.d(String.format(DEBUG_TAG, TAG), "Getting auth token for account: " + account.name + " of type: " + authTokenType);
        }

        final Bundle result = new Bundle();
        String authToken = mAuthenticationManager.getAuthToken(account, authTokenType);
        if (DEBUG) {
            Log.d(String.format(DEBUG_TAG, TAG), "AuthenticationManager returned: " + authToken);
        }

        // if we have an auth token we can return it now
        if (!TextUtils.isEmpty(authToken)) {
            if (DEBUG) {
                Log.d(String.format(DEBUG_TAG, TAG), "We have an auth token. Returning " + authToken);
            }
            result.putString(AuthenticatorActivity.KEY_ACCOUNT_NAME, account.name);
            result.putString(AuthenticatorActivity.KEY_ACCOUNT_TYPE, account.type);
            result.putString(AuthenticatorActivity.KEY_AUTHTOKEN, authToken);
            return result;
        }

        if (DEBUG) {
            Log.d(String.format(DEBUG_TAG, TAG), "Wasn't able to get an auth token. Requiring user to login.");
        }

        // If we get here, then we couldn't access the user's password - so we
        // need to re-prompt them for their credentials. We do that by creating
        // an intent to display our AuthenticatorActivity.
        final Intent intent = new Intent(mContext, mLoginClass);
        intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
        intent.putExtra(AuthenticatorActivity.KEY_ACCOUNT_TYPE, account.type);
        intent.putExtra(AuthenticatorActivity.KEY_AUTHTOKEN_TYPE, authTokenType);
        intent.putExtra(AuthenticatorActivity.KEY_ACCOUNT_NAME, account.name);

        result.putParcelable(AccountManager.KEY_INTENT, intent);

        return result;
    }

    @Override public String getAuthTokenLabel(String authTokenType) {
        return authTokenType;
    }

    @Override
    public Bundle confirmCredentials(AccountAuthenticatorResponse response, Account account, Bundle options) throws NetworkErrorException {
        return null;
    }

    @Override
    public Bundle updateCredentials(AccountAuthenticatorResponse response, Account account, String authTokenType, Bundle options) throws NetworkErrorException {
        return null;
    }

    @Override
    public Bundle hasFeatures(AccountAuthenticatorResponse response, Account account, String[] features) throws NetworkErrorException {
        return null;
    }

    @Override
    public Bundle editProperties(AccountAuthenticatorResponse response, String accountType) {
        return null;
    }
}
