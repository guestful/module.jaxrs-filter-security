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
package com.guestful.jaxrs.security.realm;

import com.guestful.jaxrs.security.LoginContext;
import com.guestful.jaxrs.security.subject.AuthenticatedSubject;
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.token.AuthenticationToken;
import com.guestful.jaxrs.security.token.LoginPasswordToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.LoginException;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class LoginPasswordRealm extends AbstractRealm {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginPasswordRealm.class);

    public LoginPasswordRealm() {
        super(LoginPasswordToken.class);
    }

    @Override
    public Subject authenticate(AuthenticationToken authToken, LoginContext loginContext) throws LoginException {
        LOGGER.trace("authenticate() Find account " + authToken);
        Account account = getAccountRepository().findAccount(authToken);
        if (account == null) {
            throw new AccountNotFoundException(String.valueOf(authToken.getToken()));
        }
        if (account.isLocked()) {
            throw new AccountLockedException(account.getPrincipal().getName());
        }
        LOGGER.trace("authenticate() Check credentials against account " + account.getPrincipal());
        if (!getCredentialsMatcher().matches(account, authToken)) {
            throw new BadCredentialException(String.valueOf(authToken.getToken()));
        }
        return new AuthenticatedSubject(
            account,
            null,
            authToken,
            getSessionConfigurations().getConfiguration(authToken.getSystem()),
            loginContext);
    }

}
