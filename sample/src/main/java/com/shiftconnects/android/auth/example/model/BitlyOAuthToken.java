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

package com.shiftconnects.android.auth.example.model;

import com.google.gson.annotations.SerializedName;
import com.shiftconnects.android.auth.model.OAuthToken;

/**
 * Object representing an oauth token from bitly
 */
public class BitlyOAuthToken implements OAuthToken {

    @SerializedName("access_token")
    private String accessToken;

    @SerializedName("refresh_token")
    private String refreshToken;

    @SerializedName("status_code")
    Integer statusCode;

    @SerializedName("data")
    String data;

    @SerializedName("status_txt")
    String statusText;

    @Override public String getAuthToken() {
        return accessToken;
    }

    @Override public String getRefreshToken() {
        return refreshToken;
    }

    @Override public long getExpiresIn() {
        return 0;
    }

    public Integer getStatusCode() {
        return statusCode;
    }

    public String getData() {
        return data;
    }

    public String getStatusText() {
        return statusText;
    }
}
