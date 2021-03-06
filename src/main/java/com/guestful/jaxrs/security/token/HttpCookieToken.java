/**
 * Copyright (C) 2013 Guestful (info@guestful.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.guestful.jaxrs.security.token;

import com.guestful.jaxrs.security.annotation.AuthScheme;

import javax.ws.rs.core.Cookie;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class HttpCookieToken extends AbstractAuthenticationToken {

    private final Cookie cookie;
    private final String system;

    public HttpCookieToken(Cookie cookie) {
        this("", cookie);
    }

    public HttpCookieToken(String system, Cookie cookie) {
        this.cookie = cookie;
        this.system = system;
    }

    @Override
    public String getSystem() {
        return system;
    }

    @Override
    public Object getToken() {
        return cookie.getValue();
    }

    @Override
    public String getScheme() {
        return AuthScheme.COOKIE.name();
    }

    @Override
    public boolean isSessionAllowed() {
        return true;
    }

    @Override
    public boolean isAuthenticationRequired() {
        return false;
    }

    public Cookie getCookie() {
        return cookie;
    }
}
