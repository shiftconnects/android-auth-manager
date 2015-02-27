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

package com.shiftconnects.android.auth.example;

import android.accounts.Account;
import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import com.shiftconnects.android.auth.AuthenticationManager;
import com.shiftconnects.android.auth.example.model.ShortenedUrl;
import com.shiftconnects.android.auth.example.util.Constants;

/**
 * This is an example of an authenticated activity. It will attempt to authenticate in {@link #onCreate(android.os.Bundle)} and
 * if there is no valid account for the provided account type and auth token type the user will be provided
 * with the login screen to login. Upon successful login a call to {@link #onAuthenticationSuccessful(String)} with the
 * auth token will be called.
 */
public class ExampleAuthenticatedActivity extends Activity implements AuthenticationManager.Callbacks, View.OnClickListener {

    private static final String TAG = ExampleAuthenticatedActivity.class.getSimpleName();

    private EditText mLongUrl;
    private EditText mShortUrl;
    private Button mShortenButton;
    private Button mLogoutButton;

    private String mAuthToken;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_example);
        mLongUrl = (EditText) findViewById(R.id.long_url);
        mShortUrl = (EditText) findViewById(R.id.short_url);
        mShortenButton = (Button) findViewById(R.id.shorten_button);
        mLogoutButton = (Button) findViewById(R.id.logout_button);
        mLogoutButton.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                logout();
            }
        });
        mShortenButton.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                shortenUrl();
            }
        });
        ExampleApplication.AUTHENTICATION_MANAGER.addCallbacks(this);
        if (TextUtils.isEmpty(mAuthToken)) {
            authenticate();
        }
    }

    private void logout() {
        Account loggedInAccount = ExampleApplication.AUTHENTICATION_MANAGER.getSingleAccountForType(Constants.ACCOUNT_TYPE);
        if (loggedInAccount != null) {
            ExampleApplication.AUTHENTICATION_MANAGER.logout(loggedInAccount, Constants.AUTH_TOKEN_TYPE);
        }
    }

    @Override protected void onDestroy() {
        super.onDestroy();
        ExampleApplication.AUTHENTICATION_MANAGER.removeCallbacks(this);
    }

    private void authenticate() {
        ExampleApplication.AUTHENTICATION_MANAGER.authenticate(this, Constants.ACCOUNT_TYPE, Constants.AUTH_TOKEN_TYPE);
    }

    @Override public void onAuthenticationCanceled() {
        mAuthToken = null;
        Log.d(TAG, "onAuthenticationCanceled()");
        finish();
    }

    @Override public void onAuthenticationSuccessful(String authToken) {
        mAuthToken = authToken;
        Log.d(TAG, "onAuthenticationSuccessful(" + authToken + ")");
    }

    @Override public void onAuthenticationNetworkError() {
        mAuthToken = null;
        Log.d(TAG, "onAuthenticationNetworkError()");
        authenticate();
    }

    @Override public void onAuthenticationFailed(Exception e) {
        mAuthToken = null;
        Log.e(TAG, "onAuthenticationFailed()", e);
        authenticate();
    }

    @Override public void onAuthenticationInvalidated(String invalidatedAuthToken) {
        mAuthToken = null;
        Log.d(TAG, "onAuthenticationInvalidated(" + invalidatedAuthToken + ")");
        authenticate();
    }

    @Override public void onClick(View v) {
        shortenUrl();
    }

    private void shortenUrl() {
        String urlToShorten = mLongUrl.getText().toString();
        // TODO the url should be checked to be valid, etc...
        if (!TextUtils.isEmpty(urlToShorten)) {
            if (!urlToShorten.startsWith("http://")) {
                urlToShorten = "http://" + urlToShorten;
            }
            new AsyncTask<String, Void, ShortenedUrl>() {

                @Override protected ShortenedUrl doInBackground(String... params) {
                    return ExampleApplication.BITLY_SERVICE.shortenUrl(mAuthToken, params[0]);
                }

                @Override protected void onPostExecute(ShortenedUrl shortenResponse) {
                    if (shortenResponse != null) {
                        if (shortenResponse.getStatusCode() == null || shortenResponse.getStatusCode() == 200) {
                            mShortUrl.setText(shortenResponse.getData().getUrl());
                        } else {
                            mShortUrl.setText("ERROR: " + shortenResponse.getStatusText());
                        }
                    }
                }

            }.execute(urlToShorten);
        }
    }
}
