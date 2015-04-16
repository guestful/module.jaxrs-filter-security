/**
 * Copyright (C) 2013 Guestful (info@guestful.com)
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.guestful.jaxrs.security.token;

import com.guestful.client.facebook.FacebookAccessToken;
import com.guestful.jaxrs.security.annotation.AuthScheme;

import javax.json.JsonObject;
import java.util.Objects;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class FacebookToken extends AbstractAuthenticationToken {

    private final String userId;
    private final String system;
    private Object accessToken;
    private String appId;
    private String signedRequest;
    private JsonObject me;

    public FacebookToken(String userId, FacebookAccessToken accessToken) {
        this("", userId, accessToken);
    }

    public FacebookToken(String system, String userId, FacebookAccessToken accessToken) {
        this(system, userId, accessToken, null, null);
    }

    public FacebookToken(String system, String userId, FacebookAccessToken accessToken, String appId, String signedRequest) {
        this.system = Objects.requireNonNull(system);
        this.userId = Objects.requireNonNull(userId);
        this.accessToken = Objects.requireNonNull(accessToken);
        this.appId = appId;
        this.signedRequest = signedRequest;
    }

    public void setAppId(String appId) {
        this.appId = appId;
    }

    public void setSignedRequest(String signedRequest) {
        this.signedRequest = signedRequest;
    }

    public JsonObject getMe() {
        return me;
    }

    public void setMe(JsonObject me) {
        this.me = me;
    }

    public String getAppId() {
        return appId;
    }

    public String getUserId() {
        return userId;
    }

    public String getSignedRequest() {
        return signedRequest;
    }

    @Override
    public Object getToken() {
        return userId;
    }

    @Override
    public Object readCredentials() {
        return accessToken;
    }

    @Override
    public String getScheme() {
        return AuthScheme.FACEBOOK.name();
    }

    @Override
    public boolean isSessionAllowed() {
        return true;
    }

    @Override
    public boolean isAuthenticationRequired() {
        return true;
    }

    @Override
    public String getSystem() {
        return system;
    }

}
