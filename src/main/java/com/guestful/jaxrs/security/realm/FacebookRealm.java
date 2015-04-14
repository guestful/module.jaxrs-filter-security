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
import com.guestful.jaxrs.security.subject.AuthenticatedSubject;
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.token.AuthenticationToken;
import com.guestful.jaxrs.security.token.PassthroughToken;

import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.LoginException;
import java.util.logging.Logger;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class FacebookRealm extends AbstractRealm {

    private static final Logger LOGGER = Logger.getLogger(FacebookRealm.class.getName());

    public FacebookRealm() {
        super(PassthroughToken.class);
    }

    @Override
    public Subject authenticate(AuthenticationToken token, LoginContext loginContext) throws LoginException {
        LOGGER.finest("authenticate() Find account for token " + token);
        Account account = getAccountRepository().findAccount(token);
        if (account == null) {
            throw new AccountNotFoundException(String.valueOf(token.getToken()));
        }
        if (account.isLocked()) {
            throw new AccountLockedException(account.getPrincipal().getName());
        }
        if (account.getPrincipal().equals(loginContext.getPrincipal()) && loginContext.getSession(false) != null) {
            LOGGER.finest("authenticate() removing old session " + loginContext.getSession().getId());
            getSessionRepository().removeSession(loginContext.getSession().getId());
        }
        return new AuthenticatedSubject(
            account,
            null,
            token,
            getSessionConfiguration(),
            loginContext);
    }

}

/*


        // additional optional verification
        if (data.signedRequest) {
            FacebookUnsignedRequest facebookUnsignedRequest = facebookClient.unsignRequest(data.signedRequest as String)
            if (facebookUserId != facebookUnsignedRequest.userId) {
                throw new NotAuthorizedException("Invalid Signed Request", "GBASICAUTH realm=\"" + uriInfo.getBaseUri() + "\"")
            }
        }


        Map guest = onError FacebookClientException, 'accessToken', 'invalid', { guestHelper.findGuestByFacebook(data.accessToken as String, APIToken.current, requestLocale) }
        if (facebookUserId != guest.facebookId) {
            throw new NotAuthorizedException("Invalid Access Token", "GBASICAUTH realm=\"" + uriInfo.getBaseUri() + "\"")
        }


*/
