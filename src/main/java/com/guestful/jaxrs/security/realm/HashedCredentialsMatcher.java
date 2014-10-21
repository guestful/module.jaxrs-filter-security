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
package com.guestful.jaxrs.security.realm;

import com.guestful.jaxrs.security.token.AuthenticationToken;
import com.guestful.jaxrs.security.util.Crypto;

import javax.security.auth.login.CredentialException;
import javax.security.auth.login.CredentialNotFoundException;
import java.util.logging.Logger;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class HashedCredentialsMatcher implements CredentialsMatcher {

    private static final Logger LOGGER = Logger.getLogger(HttpCookieRealm.class.getName());

    private final int hashIterations;

    public HashedCredentialsMatcher() {
        this(3);
    }

    public HashedCredentialsMatcher(int hashIterations) {
        this.hashIterations = hashIterations;
    }

    @Override
    public boolean matches(Account account, AuthenticationToken token) throws CredentialException {
        Object tokenCredentials = token.readCredentials();
        if (tokenCredentials == null) {
            throw new CredentialNotFoundException("token");
        }
        Object accountCredentials = account.getCredentials();
        if (accountCredentials == null) {
            throw new CredentialNotFoundException("account");
        }
        String hashed = Crypto.sha512(tokenCredentials.toString(), account.getPrincipal().getName(), hashIterations);
        LOGGER.finest("Computed hash: " + hashed);
        return accountCredentials.toString().equals(hashed);
    }

}
