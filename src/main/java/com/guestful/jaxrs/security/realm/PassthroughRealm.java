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
import com.guestful.jaxrs.security.token.PassthroughToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.LoginException;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class PassthroughRealm extends AbstractRealm {

    private static final Logger LOGGER = LoggerFactory.getLogger(PassthroughRealm.class);

    public PassthroughRealm() {
        super(PassthroughToken.class);
    }

    @Override
    public Subject authenticate(AuthenticationToken authToken, LoginContext loginContext) throws LoginException {
        LOGGER.trace("authenticate() {}", authToken);
        Account account = getAccountRepository().findAccount(authToken);
        if (account == null) {
            throw new AccountNotFoundException(authToken.toString());
        }
        if (account.isLocked()) {
            throw new AccountLockedException(account.getPrincipal().getName());
        }
        LOGGER.trace("authenticate() {} - found account {}", authToken, account);
        return new AuthenticatedSubject(
            account,
            null,
            authToken,
            getSessionConfigurations().getConfiguration(authToken.getSystem()),
            loginContext);
    }

}
