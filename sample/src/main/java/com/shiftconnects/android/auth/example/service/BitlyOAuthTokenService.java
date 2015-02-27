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

package com.shiftconnects.android.auth.example.service;

import android.util.Base64;

import com.shiftconnects.android.auth.example.model.BitlyOAuthToken;
import com.shiftconnects.android.auth.service.OAuthTokenService;

import java.nio.charset.Charset;

/**
 * Service which wraps a retrofit Bit.ly service in order to process a request before trying to retrieve
 * an oauth token
 */
public class BitlyOAuthTokenService implements OAuthTokenService<BitlyOAuthToken> {

    private BitlyRetrofitService mRetrofitService;

    public BitlyOAuthTokenService(BitlyRetrofitService bitlyRetrofitService) {
        mRetrofitService = bitlyRetrofitService;
    }

    @Override public BitlyOAuthToken getTokenWithPassword(String clientId, String clientSecret, String userName, String password) {
        String clientIdAndSecret = clientId + ":" + clientSecret;
        String authorizationHeader = BitlyRetrofitService.BASIC + " " + Base64.encodeToString(clientIdAndSecret.getBytes(Charset.forName("UTF-8")), Base64.NO_WRAP);
        BitlyOAuthToken response = mRetrofitService.getToken(authorizationHeader, GrantType.password.name(), userName, password);
        if (response.getStatusCode() != null && response.getStatusCode() != 200) {
            return null;
        }
        return response;
    }

    @Override public BitlyOAuthToken getTokenWithRefreshToken(String clientId, String clientSecret, String refreshToken) {
        throw new UnsupportedOperationException("This service does not support refresh token auth");
    }

    @Override public BitlyOAuthToken getTokenWithClientCredentials(String clientId, String clientSecret) {
        throw new UnsupportedOperationException("This service does not support client credential auth");
    }
}
