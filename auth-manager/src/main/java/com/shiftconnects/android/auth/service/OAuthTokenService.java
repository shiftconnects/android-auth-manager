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

package com.shiftconnects.android.auth.service;

import com.shiftconnects.android.auth.model.OAuthToken;

/**
 * Service which retrieves an {@link com.shiftconnects.android.auth.model.OAuthToken}
 * with via different grant types.
 *
 * One use of this interface would be to extend it as a retrofit service to interface to an authorization
 * server.
 */
@SuppressWarnings("unused")
public interface OAuthTokenService<T extends OAuthToken> {
    T getTokenWithPassword(String clientId, String clientSecret, String userName, String password);
    T getTokenWithRefreshToken(String clientId, String clientSecret, String refreshToken);
    T getTokenWithClientCredentials(String clientId, String clientSecret);

    public static enum GrantType {
        password,
        refresh_token,
        client_credentials
    }
}
