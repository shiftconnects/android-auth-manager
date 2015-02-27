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

import com.shiftconnects.android.auth.example.model.BitlyOAuthToken;
import com.shiftconnects.android.auth.example.model.ShortenedUrl;

import retrofit.http.Field;
import retrofit.http.FormUrlEncoded;
import retrofit.http.GET;
import retrofit.http.Header;
import retrofit.http.Headers;
import retrofit.http.POST;
import retrofit.http.Query;

/**
 * Retrofit service which interfaces with the bitly api
 */
public interface BitlyRetrofitService {
    public static final String ACCEPT_JSON_HEADER = "Accept: application/json";
    public static final String BASIC = "Basic";

    @Headers({ACCEPT_JSON_HEADER})
    @FormUrlEncoded
    @POST("/oauth/access_token")
    BitlyOAuthToken getToken(@Header("Authorization") String authorizationHeader,
                                     @Field("grant_type") String grantType,
                                     @Field("username") String username,
                                     @Field("password") String password);


    @Headers({ACCEPT_JSON_HEADER})
    @GET("/v3/shorten")
    ShortenedUrl shortenUrl(@Query("access_token") String accessToken, @Query("longUrl") String longUrl);
}
