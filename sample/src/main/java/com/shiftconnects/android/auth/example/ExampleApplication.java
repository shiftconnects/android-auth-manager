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

import android.accounts.AccountManager;
import android.app.Application;

import com.google.gson.Gson;
import com.shiftconnects.android.auth.AccountAuthenticator;
import com.shiftconnects.android.auth.AuthenticationManager;
import com.shiftconnects.android.auth.example.service.BitlyOAuthTokenService;
import com.shiftconnects.android.auth.example.service.BitlyRetrofitService;
import com.shiftconnects.android.auth.example.util.ExampleCrypto;
import com.shiftconnects.android.auth.example.util.GsonConverter;

import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

import retrofit.RestAdapter;

/**
 * Created by mattkranzler on 2/25/15.
 */
public class ExampleApplication extends Application {

    private static final String BITLY_CLIENT_ID = "your-bitly-client-id";
    private static final String BITLY_CLIENT_SECRET = "your-bitly-client-secret";

    public static AccountAuthenticator ACCOUNT_AUTHENTICATOR;
    public static AuthenticationManager AUTHENTICATION_MANAGER;
    public static BitlyRetrofitService BITLY_SERVICE;

    @Override public void onCreate() {
        super.onCreate();

        try {
            BITLY_SERVICE = new RestAdapter.Builder()
                    .setEndpoint("https://api-ssl.bitly.com")
                    .setLogLevel(RestAdapter.LogLevel.FULL)
                    .setConverter(new GsonConverter(new Gson()))
                    .build()
                    .create(BitlyRetrofitService.class);
            AUTHENTICATION_MANAGER = new AuthenticationManager(
                    AccountManager.get(this),
                    new BitlyOAuthTokenService(BITLY_SERVICE),
                    new ExampleCrypto(ExampleCrypto.generateSalt(), ExampleCrypto.generateIV()), // TODO should save off salt and iv somewhere so we aren't generating every time
                    BITLY_CLIENT_ID,
                    BITLY_CLIENT_SECRET
            );
            ACCOUNT_AUTHENTICATOR = new AccountAuthenticator(
                    this,
                    ExampleLoginActivity.class,
                    AUTHENTICATION_MANAGER
            );
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }
}
