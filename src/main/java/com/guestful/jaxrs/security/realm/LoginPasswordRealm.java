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
import com.guestful.jaxrs.security.subject.DefaultSubject;
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.token.AuthenticationToken;
import com.guestful.jaxrs.security.token.LoginPasswordToken;

import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.LoginException;
import java.util.logging.Logger;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class LoginPasswordRealm extends AbstractRealm {

    private static final Logger LOGGER = Logger.getLogger(LoginPasswordRealm.class.getName());

    public LoginPasswordRealm() {
        super(LoginPasswordToken.class);
    }

    @Override
    public Subject authenticate(AuthenticationToken token, LoginContext loginContext) throws LoginException {
        LOGGER.finest("authenticate() Find account " + token);
        Account account = getAccountRepository().findAccount(token);
        if (account == null) {
            throw new AccountNotFoundException(String.valueOf(token.getToken()));
        }
        if (account.isLocked()) {
            throw new AccountLockedException(account.getPrincipal().getName());
        }
        LOGGER.finest("authenticate() Check credentials against account " + account.getPrincipal());
        if (!getCredentialsMatcher().matches(account, token)) {
            throw new BadCredentialException(String.valueOf(token.getToken()));
        }
        if (account.getPrincipal().equals(loginContext.getPrincipal()) && loginContext.getSession(false) != null) {
            LOGGER.finest("logout() removing old session " + loginContext.getSession().getId());
            getSessionRepository().removeSession(loginContext.getPrincipal(), loginContext.getSession().getId());
        }
        return new DefaultSubject(
            account,
            null,
            token,
            getSessionConfiguration(),
            loginContext);
    }

}
