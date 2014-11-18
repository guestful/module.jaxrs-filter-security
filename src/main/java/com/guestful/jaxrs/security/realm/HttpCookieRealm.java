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

import com.guestful.jaxrs.security.LoginContext;
import com.guestful.jaxrs.security.filter.SessionCookieFilter;
import com.guestful.jaxrs.security.session.DefaultSession;
import com.guestful.jaxrs.security.session.Session;
import com.guestful.jaxrs.security.session.StoredSession;
import com.guestful.jaxrs.security.subject.DefaultSubject;
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.token.AuthenticationToken;
import com.guestful.jaxrs.security.token.HttpCookieToken;
import com.guestful.jaxrs.security.util.Crypto;

import javax.security.auth.login.*;
import java.util.logging.Logger;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class HttpCookieRealm extends AbstractRealm {

    private static final Logger LOGGER = Logger.getLogger(HttpCookieRealm.class.getName());

    public HttpCookieRealm() {
        super(HttpCookieToken.class);
    }

    @Override
    public Subject authenticate(AuthenticationToken token, LoginContext loginContext) throws LoginException {
        LOGGER.finest("authenticate() " + token);
        String sessionId = token.getToken() == null ? null : token.getToken().toString();
        if (!Crypto.isUuid(sessionId)) {
            throw new FailedLoginException("Invalid session ID");
        }
        StoredSession storedSession = getSessionRepository().findSession(sessionId);
        if (storedSession != null && storedSession.isExpired()) {
            LOGGER.finest("authenticate() Removing expired session " + sessionId);
            getSessionRepository().removeSession(storedSession.getPrincipal(), storedSession.getId());
            storedSession = null;
        }
        if (storedSession != null && !storedSession.getOrigin().equals(loginContext.getOrigin())) {
            LOGGER.finest("authenticate() Removing stolen session " + sessionId + ": session origin=" + storedSession.getOrigin() + " vs request origin=" + loginContext.getOrigin());
            getSessionRepository().removeSession(storedSession.getPrincipal(), storedSession.getId());
            storedSession = null;
        }
        if (storedSession == null) {
            throw new CredentialExpiredException(sessionId);
        }
        Session session = new DefaultSession(storedSession);
        LOGGER.finest("authenticate() Found session " + session);
        Account account = getAccountRepository().findAccount(storedSession.getPrincipal());
        if (account == null) {
            throw new AccountNotFoundException(storedSession.getPrincipal().getName());
        }
        LOGGER.finest("authenticate() Found account " + account.getPrincipal());
        if (account.isLocked()) {
            throw new AccountLockedException(account.getPrincipal().getName());
        }
        return new DefaultSubject(
            account,
            session,
            token,
            getSessionConfiguration(),
            loginContext);
    }

    @Override
    public void onLogout(Subject subject) {
        LOGGER.finest("onLogout() " + subject.getPrincipal());
        subject.getRequest().setProperty(SessionCookieFilter.SESSION_COOKIE_EXPIRED, true);
    }

}
