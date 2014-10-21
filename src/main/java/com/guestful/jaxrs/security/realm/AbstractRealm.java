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

import com.guestful.jaxrs.security.session.SessionConfiguration;
import com.guestful.jaxrs.security.session.SessionRepository;
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.token.AuthenticationToken;

import javax.inject.Inject;
import java.util.Arrays;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public abstract class AbstractRealm implements Realm {

    private CredentialsMatcher credentialsMatcher;
    private AccountRepository accountRepository;
    private SessionConfiguration sessionConfiguration;
    private SessionRepository sessionRepository;

    private final Class<?>[] types;

    protected AbstractRealm(Class<?>... types) {
        this.types = types;
    }

    public CredentialsMatcher getCredentialsMatcher() {
        return credentialsMatcher;
    }

    @Inject
    public void setCredentialsMatcher(CredentialsMatcher credentialsMatcher) {
        this.credentialsMatcher = credentialsMatcher;
    }

    public AccountRepository getAccountRepository() {
        return accountRepository;
    }

    @Inject
    public void setAccountRepository(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    public SessionConfiguration getSessionConfiguration() {
        return sessionConfiguration;
    }

    @Inject
    public void setSessionConfiguration(SessionConfiguration sessionConfiguration) {
        this.sessionConfiguration = sessionConfiguration;
    }

    public SessionRepository getSessionRepository() {
        return sessionRepository;
    }

    @Inject
    public void setSessionRepository(SessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        for (Class<?> type : types) {
            if (type.isInstance(token)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void onLogout(Subject subject) {
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " (" + String.join(",", (Iterable<String>) Arrays.asList(types).stream().map(Class::getSimpleName)::iterator) + ")";
    }

}
