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
import android.app.Activity;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Log;

import com.shiftconnects.android.auth.model.OAuthToken;
import com.shiftconnects.android.auth.service.OAuthTokenService;
import com.shiftconnects.android.auth.util.Constants;
import com.shiftconnects.android.auth.util.Crypto;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.Date;

/**
 * Manages interfacing the {@link android.accounts.AccountManager} with authentication for the app
 */
public class AuthenticationManager implements AuthTokenCallback.Callbacks {
    private static final String TAG = AuthenticationManager.class.getSimpleName();
    private static final boolean DEBUG = false;

    public static interface Callbacks {

        /**
         * Authentication was canceled. (The user backed out of the login activity)
         */
        void onAuthenticationCanceled();

        /**
         * Authentication was successful.
         * @param authToken - the valid auth token
         */
        void onAuthenticationSuccessful(String authToken);

        /**
         * Authentication failed due to a network related error (the auth server is down or the user
         * doesn't have a valid internet connection).
         */
        void onAuthenticationNetworkError();

        /**
         * Authentication failed due to an unknown error.
         * @param e - the unknown error
         */
        void onAuthenticationFailed(Exception e);

        /**
         * Authentication was invalidated (most likely due to logout).
         * @param invalidatedAuthToken - the auth token that is no longer valid
         */
        void onAuthenticationInvalidated(String invalidatedAuthToken);
    }

    private AccountManager mAccountManager;
    private OAuthTokenService mOAuthTokenService;
    private Crypto mCrypto;
    private String mClientId;
    private String mClientSecret;
    private ArrayList<Callbacks> mCallbacks;

    /**
     * Creates a new AuthenticationManager
     * @param accountManager - the android {@link android.accounts.AccountManager}
     * @param oAuthTokenService - the {@link com.shiftconnects.android.auth.service.OAuthTokenService} to retrieve OAuth tokens
     * @param crypto - the {@link com.shiftconnects.android.auth.util.Crypto} to use for encryption/decryption
     * @param clientId - the application client id to be used for OAuth
     * @param clientSecret - the application client secret to be used for OAuth
     */
    public AuthenticationManager(AccountManager accountManager, OAuthTokenService oAuthTokenService, Crypto crypto,
                                 String clientId, String clientSecret) {
        mAccountManager = accountManager;
        mOAuthTokenService = oAuthTokenService;
        mCrypto = crypto;
        mClientId = clientId;
        mClientSecret = clientSecret;
        mCallbacks = new ArrayList<>();
    }

    public boolean addCallbacks(Callbacks callbacks) {
        return mCallbacks.add(callbacks);
    }

    public boolean removeCallbacks(Callbacks callbacks) {
        return mCallbacks.remove(callbacks);
    }

    /**
     * Gets the {@link android.accounts.Account} for the provided account name and type
     * @param accountName - the {@link android.accounts.Account#name}
     * @param accountType - the {@link android.accounts.Account#type}
     * @return the {@link android.accounts.Account} if it exists, null if not
     */
    @Nullable
    public Account getAccountByNameForType(@NotNull String accountName, @NotNull String accountType) {
        validateAccountName(accountName);
        validateAccountType(accountType);

        final Account[] accounts = mAccountManager.getAccountsByType(accountType);
        for (Account account : accounts) {
            if (TextUtils.equals(accountName, account.name)) {
                return account;
            }
        }
        return null;
    }

    /**
     * Returns a single {@link android.accounts.Account} for the provided {@link android.accounts.Account#type}
     * if one exists
     * @param accountType - the {@link android.accounts.Account#type}. Must NOT be null or empty
     * @return an {@link android.accounts.Account} if one exists, null if none exist
     */
    @Nullable
    public Account getSingleAccountForType(@NotNull String accountType) {
        validateAccountType(accountType);

        final Account[] accounts = mAccountManager.getAccountsByType(accountType);
        if (accounts.length == 1) {
            return accounts[0];
        }
        return null;
    }

    /**
     * Gets the auth token from {@link android.accounts.AccountManager}. It will attempt to refresh the auth token
     * if a refresh token is available and an existing auth token has expired. This call is synchronous so DO NOT
     * call on UI thread
     * @param account - the {@link android.accounts.Account} for which to get the auth token. Must NOT be null and
     *                must have a valid {@link android.accounts.Account#name}
     * @param authTokenType - the auth token type
     * @return the auth token if available
     */
    @Nullable
    public synchronized String getAuthToken(@NotNull Account account, @NotNull String authTokenType) {
        validateAccount(account);
        validateAccountName(account.name);
        validateAccountType(account.type);
        validateAuthTokenType(authTokenType);

        String authToken = mAccountManager.peekAuthToken(account, authTokenType);
        if (TextUtils.isEmpty(authToken)) {
            if (DEBUG) {
                Log.d(TAG, "No auth token is available for the account :(");
            }
        } else {
            String expiration = mAccountManager.getUserData(account, Constants.KEY_TOKEN_EXPIRATION_TIME);
            if (!TextUtils.isEmpty(expiration)) {
                final long expirationTime = Long.valueOf(expiration);
                if (System.currentTimeMillis() > expirationTime) {
                    if (DEBUG) {
                        Log.d(TAG, "Auth token has expired. Expiration time [" + new Date(expirationTime) + "]. Attempting to get a new token...");
                    }
                    authToken = getNewAuthToken(account, authTokenType);
                }
            }
        }

        return authToken;
    }

    private String getNewAuthToken(@NotNull Account account, @NotNull String authTokenType) {
        String isClientCredentials = mAccountManager.getUserData(account, Constants.KEY_IS_CLIENT_CREDENTIALS);
        if (TextUtils.equals(isClientCredentials, Constants.VALUE_IS_CLIENT_CREDENTIALS)) {
            return getNewAuthTokenWithClientCredentials(account, authTokenType);
        } else {
            return getNewAuthTokenWithRefreshToken(account, authTokenType);
        }
    }

    private String getNewAuthTokenWithRefreshToken(@NotNull Account account, @NotNull String authTokenType) {
        final String encryptedRefreshToken = getEncryptedRefreshToken(account);
        if (TextUtils.isEmpty(encryptedRefreshToken)) {
            if (DEBUG) {
                Log.d(TAG, "failed to refresh auth token due to no refresh token available");
            }
            authenticationFailed(account, authTokenType);
            return null;
        }
        final String decryptedRefreshToken = decryptRefreshToken(account, encryptedRefreshToken);
        if (TextUtils.isEmpty(decryptedRefreshToken)) {
            if (DEBUG) {
                Log.d(TAG, "failed to refresh token due to a decryption failure");
            }
            authenticationFailed(account, authTokenType);
            return null;
        }
        final long currentTime = System.currentTimeMillis();
        final OAuthToken response = mOAuthTokenService.getTokenWithRefreshToken(mClientId, mClientSecret, decryptedRefreshToken);
        if (response == null) {
            if (DEBUG) {
                Log.d(TAG, "failed to refresh auth token due to an authentication exception");
            }
            authenticationFailed(account, authTokenType);
            return null;
        }

        // invalidate the old token
        invalidateAuthTokenForAccount(account, authTokenType);

        Log.d(TAG, "received a new auth token from the oauth service with a refresh token.");
        saveAuthentication(account, authTokenType, OAuthTokenService.GrantType.refresh_token, response, currentTime);

        return response.getAuthToken();
    }

    private String getNewAuthTokenWithClientCredentials(@NotNull Account account, @NotNull String authTokenType) {
        final long currentTime = System.currentTimeMillis();
        final OAuthToken response = mOAuthTokenService.getTokenWithClientCredentials(mClientId, mClientSecret);
        if (response == null) {
            if (DEBUG) {
                Log.d(TAG, "failed to refresh auth token due to an authentication exception");
            }
            authenticationFailed(account, authTokenType);
            return null;
        }

        // invalidate the old token
        invalidateAuthTokenForAccount(account, authTokenType);

        if (DEBUG) {
            Log.d(TAG, "received a new auth token from the oauth service with client credentials.");
        }
        saveAuthentication(account, authTokenType, OAuthTokenService.GrantType.client_credentials, response, currentTime);

        return response.getAuthToken();
    }

    private void authenticationFailed(Account account, String authTokenType) {
        logout(account, authTokenType);
        notifyCallbacksAuthenticationFailed(new Exception("Was unable to refresh auth token"));
    }

    public void setUserData(@NotNull Account account, @NotNull String key, String value) {
        validateAccount(account);
        mAccountManager.setUserData(account, key, value);
    }

    public String getUserData(@NotNull Account account, @NotNull String key) {
        validateAccount(account);
        return mAccountManager.getUserData(account, key);
    }

    /**
     * Begins the authentication process. If the user has already logged in and has a valid auth token,
     * a {@link com.shiftconnects.android.auth.AuthenticationManager.Callbacks#onGetAuthTokenSuccessful(String)} will be called. If
     * the user is logged in but has an invalid auth token, an attempt to refresh it will be made and
     * upon success a {@link com.shiftconnects.android.auth.AuthenticationManager.Callbacks#onGetAuthTokenSuccessful(String)} will
     * be posted. If the user isn't logged in, {@link android.accounts.AccountManager} will handle
     * launching the Activity to be used to authenticate the user.
     * @param activity - the calling activity. Must NOT be null
     * @param accountType - the {@link android.accounts.AccountManager#KEY_ACCOUNT_TYPE}. Must NOT be null or empty
     * @param authTokenType - the auth token type. Must NOT be null or empty
     */
    public void authenticate(@NotNull Activity activity, @NotNull String accountType, @NotNull String authTokenType) {
        validateActivity(activity);
        validateAccountType(accountType);
        validateAuthTokenType(authTokenType);

        // see if we already have a logged in account for this account type
        Account account = getSingleAccountForType(accountType);
        if (account != null) {
            mAccountManager.getAuthToken(
                    account,
                    authTokenType,
                    null,
                    activity,
                    new AuthTokenCallback(mAccountManager, authTokenType, this),
                    null
            );
        } else {
            mAccountManager.addAccount(
                    accountType,
                    authTokenType,
                    null,
                    null,
                    activity,
                    new AuthTokenCallback(mAccountManager, authTokenType, this),
                    null
            );
        }
    }

    /**
     * Logs a user into the app by retrieving an auth token from the oauth service and saving it along with the account in {@link android.accounts.AccountManager}
     * @param userName - the userName of the user. Must NOT be null or empty
     * @param password - the user's password. Must NOT be null or empty
     * @param accountType - the {@link android.accounts.AccountManager#KEY_ACCOUNT_TYPE}. Must NOT be null or empty
     * @param authTokenType - the auth token type. Must NOT be null or empty
     * @param newAccount - if true, this is a new account
     * @return the valid access token upon login
     */
    @NotNull
    public String loginWithUserNamePassword(@NotNull String userName, @NotNull String password, @NotNull String accountType, @NotNull String authTokenType, boolean newAccount) {
        validateUserName(userName);
        validatePassword(password);
        validateAccountType(accountType);
        validateAuthTokenType(authTokenType);

        Account account = new Account(userName, accountType);
        final long currentTime = System.currentTimeMillis();
        OAuthToken response = mOAuthTokenService.getTokenWithPassword(mClientId, mClientSecret, userName, password);
        if (newAccount) {
            mAccountManager.addAccountExplicitly(account, null, null);
        }
        saveAuthentication(account, authTokenType, OAuthTokenService.GrantType.password, response, currentTime);
        return response.getAuthToken();
    }

    public String loginWithClientCredentials(@NotNull String accountName, @NotNull String accountType, @NotNull String authTokenType) {
        validateAccountName(accountName);
        validateAccountType(accountType);
        validateAuthTokenType(authTokenType);

        Account account = new Account(accountName, accountType);
        final long currentTime = System.currentTimeMillis();
        OAuthToken response = mOAuthTokenService.getTokenWithClientCredentials(mClientId, mClientSecret);
        mAccountManager.addAccountExplicitly(account, null, null);
        saveAuthentication(account, authTokenType, OAuthTokenService.GrantType.client_credentials, response, currentTime);
        return response.getAuthToken();
    }

    /**
     * Logs out the account, keeping it on the device
     * @param account - the logged in {@link android.accounts.Account}. Must NOT be null
     * @param authTokenType - the auth token type. Must NOT be null or empty
     */
    public void logout(@NotNull Account account, @NotNull String authTokenType) {
        validateAccount(account);
        validateAccountName(account.name);
        validateAccountType(account.type);
        validateAuthTokenType(authTokenType);

        final String authToken = mAccountManager.peekAuthToken(account, authTokenType);
        final String accountType = account.type;

        mAccountManager.removeAccount(account, new AccountManagerCallback<Boolean>() {
            @Override public void run(AccountManagerFuture<Boolean> future) {
                if (!TextUtils.isEmpty(authToken)) {
                    notifyCallbacksAuthenticationInvalidated(authToken);
                    mAccountManager.invalidateAuthToken(accountType, authToken);
                }
            }
        }, new Handler(Looper.getMainLooper()));
    }

    private String getEncryptedRefreshToken(Account account) {
        return mAccountManager.getUserData(account, Constants.KEY_REFRESH_TOKEN);
    }

    private String decryptRefreshToken(Account account, String encryptedRefreshToken) {
        String decryptedRefreshToken = null;
        try {
            decryptedRefreshToken = mCrypto.decrypt(account.name, encryptedRefreshToken);
        } catch (Exception e) {
            Log.e(TAG, "Failed to decrypt the refresh token", e);
        }
        return decryptedRefreshToken;
    }

    private void saveAuthentication(@NotNull Account account, @NotNull String authTokenType, @NotNull OAuthTokenService.GrantType grantType,
                                    @NotNull OAuthToken token, long requestTime) {

        final String authToken = token.getAuthToken();

        // set the auth token in AccountManager
        if (DEBUG) {
            Log.d(TAG, "setting auth token in AccountManager: " + authToken);
        }
        mAccountManager.setAuthToken(account, authTokenType, authToken);

        if (token.getExpiresIn() > 0) {
            final long expirationTime = requestTime + (token.getExpiresIn() * 1000); // convert to milliseconds
            if (DEBUG) {
                Log.d(TAG, "auth token expires [" + new Date(expirationTime) + "]");
            }
            mAccountManager.setUserData(account, Constants.KEY_TOKEN_EXPIRATION_TIME, String.valueOf(expirationTime));
        }

        if (grantType == OAuthTokenService.GrantType.client_credentials) {
            if (DEBUG) {
                Log.d(TAG, "grant type is client_credentials, flagging in account manager.");
            }

            // set flag in account manager
            mAccountManager.setUserData(account, Constants.KEY_IS_CLIENT_CREDENTIALS, Constants.VALUE_IS_CLIENT_CREDENTIALS);

        } else if (!TextUtils.isEmpty(token.getRefreshToken())) {
            if (DEBUG) {
                Log.d(TAG, "storing refresh token in account manager.");
            }

            // encrypt the refresh token
            try {
                String encryptedRefreshToken = mCrypto.encrypt(account.name, token.getRefreshToken());

                // add other data to account manager
                mAccountManager.setUserData(account, Constants.KEY_REFRESH_TOKEN, encryptedRefreshToken);

            // if we get here due to an encryption failure then we will just not save the refresh token which will require them to login again
            } catch (Exception e) {
                Log.e(TAG, "Unable to save refresh token.", e);
            }
        }
    }

    private void invalidateAuthTokenForAccount(@NotNull Account account, @NotNull String authTokenType) {
        mAccountManager.invalidateAuthToken(account.type, mAccountManager.peekAuthToken(account, authTokenType));
    }

    //region validations
    private void validateAccount(Account account) {
        if (account == null) {
            throw new IllegalArgumentException("Parameter account cannot be null");
        }
    }

    private void validateAccountName(String accountName) {
        if (TextUtils.isEmpty(accountName)) {
            throw new IllegalArgumentException("Parameter accountName cannot be empty");
        }
    }

    private void validateAccountType(String accountType) {
        if (TextUtils.isEmpty(accountType)) {
            throw new IllegalArgumentException("Parameter accountType cannot be empty");
        }
    }

    private void validateAuthTokenType(String authTokenType) {
        if (TextUtils.isEmpty(authTokenType)) {
            throw new IllegalArgumentException("Parameter authTokenType cannot be null or empty");
        }
    }

    private void validateActivity(Activity activity) {
        if (activity == null) {
            throw new IllegalArgumentException("Parameter activity cannot be null");
        }
    }

    private void validateUserName(String userName) {
        if (TextUtils.isEmpty(userName)) {
            throw new IllegalArgumentException("Parameter userName cannot be null or empty");
        }
    }

    private void validatePassword(String password) {
        if (TextUtils.isEmpty(password)) {
            throw new IllegalArgumentException("Parameter password cannot be null or empty");
        }
    }

    //endregion

    //region getAuthTokenCallbacks
    @Override public void onGetAuthTokenCanceled() {
        notifyCallbacksAuthenticationCanceled();
    }

    @Override public void onGetAuthTokenSuccessful(String authToken) {
        notifyCallbacksAuthenticationSuccessful(authToken);
    }

    @Override public void onGetAuthTokenNetworkError() {
        notifyCallbacksAuthenticationNetworkError();
    }

    @Override public void onGetAuthTokenFailed(Exception e) {
        notifyCallbacksAuthenticationFailed(e);
    }
    //endregion

    //region notify callbacks
    private void notifyCallbacksAuthenticationCanceled() {
        for (Callbacks callbacks : mCallbacks) {
            callbacks.onAuthenticationCanceled();
        }
    }

    private void notifyCallbacksAuthenticationSuccessful(String authToken) {
        for (Callbacks callbacks : mCallbacks) {
            callbacks.onAuthenticationSuccessful(authToken);
        }
    }

    private void notifyCallbacksAuthenticationNetworkError() {
        for (Callbacks callbacks : mCallbacks) {
            callbacks.onAuthenticationNetworkError();
        }
    }

    private void notifyCallbacksAuthenticationFailed(Exception e) {
        for (Callbacks callbacks : mCallbacks) {
            callbacks.onAuthenticationFailed(e);
        }
    }

    private void notifyCallbacksAuthenticationInvalidated(String invalidatedAuthToken) {
        for (Callbacks callbacks : mCallbacks) {
            callbacks.onAuthenticationInvalidated(invalidatedAuthToken);
        }
    }
    //endregion
}
