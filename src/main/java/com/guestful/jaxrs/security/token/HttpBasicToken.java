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

import com.guestful.jaxrs.security.annotation.AuthScheme;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class HttpBasicToken extends LoginPasswordToken {

    public HttpBasicToken(AuthScheme scheme, String login, String password) {
        this(null, scheme, login, password);
    }

    public HttpBasicToken(String realm, AuthScheme scheme, String login, String password) {
        super(realm, scheme, login, password);
        if (scheme != AuthScheme.BASIC && scheme != AuthScheme.BASICAUTH) {
            throw new IllegalStateException("Bad scheme for " + getClass().getSimpleName() + ": " + getScheme());
        }
    }

    @Override
    public boolean isSessionAllowed() {
        return false;
    }

    @Override
    public boolean isAuthenticationRequired() {
        return true;
    }
}
