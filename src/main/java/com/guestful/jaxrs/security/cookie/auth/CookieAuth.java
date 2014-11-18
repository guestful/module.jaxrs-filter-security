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
package com.guestful.jaxrs.security.cookie.auth;

import com.guestful.jaxrs.security.AuthenticationException;

import javax.ws.rs.core.UriInfo;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 * @date 2014-11-18
 */
public class CookieAuth {

    private final UriInfo uriInfo;

    public CookieAuth(UriInfo uriInfo) {
        this.uriInfo = uriInfo;
    }

    public void replace(String value) {

    }
    public void remember(String realm, String value) {

    }

    public void clear() {
        //new NewCookie(cookie, null, 0, EXPIRED, false, true)
    }

    public String getValue() {
        return null;
    }

    public AuthenticationException failed(String message) {
        return new AuthenticationException(message, uriInfo);
    }
}
