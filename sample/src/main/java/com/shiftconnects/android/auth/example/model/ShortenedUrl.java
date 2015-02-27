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

/**
 * Object wrapping the response from shortening a url with bitly
 */
public class ShortenedUrl {

    @SerializedName("data")
    private Data data;

    @SerializedName("status_code")
    private Integer statusCode;

    @SerializedName("status_txt")
    private String statusText;

    public Data getData() {
        return data;
    }

    public Integer getStatusCode() {
        return statusCode;
    }

    public String getStatusText() {
        return statusText;
    }

    public static class Data {

        @SerializedName("url")
        private String url;

        @SerializedName("long_url")
        private String longUrl;

        public String getUrl() {
            return url;
        }

        public String getLongUrl() {
            return longUrl;
        }
    }
}
