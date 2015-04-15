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

import com.guestful.client.facebook.FacebookAccessToken;
import com.guestful.client.facebook.FacebookClient;
import com.guestful.client.facebook.FacebookUnsignedRequest;
import com.guestful.jaxrs.security.LoginContext;
import com.guestful.jaxrs.security.subject.AuthenticatedSubject;
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.token.AuthenticationToken;
import com.guestful.jaxrs.security.token.FacebookToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.json.JsonObject;
import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.LoginException;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class FacebookRealm extends AbstractRealm {

    private static final Logger LOGGER = LoggerFactory.getLogger(FacebookRealm.class);

    private FacebookClient facebookClient;

    public FacebookRealm() {
        super(FacebookToken.class);
    }

    @Inject
    public void setFacebookClient(FacebookClient facebookClient) {
        this.facebookClient = facebookClient;
    }

    @Override
    public Subject authenticate(AuthenticationToken token, LoginContext loginContext) throws LoginException {
        LOGGER.trace("authenticate() {}", token);
        FacebookToken facebookToken = (FacebookToken) token;
        // verification signature if possible
        if (facebookToken.getSignedRequest() != null && facebookToken.getUserId() != null) {
            FacebookUnsignedRequest facebookUnsignedRequest = facebookClient.unsignRequest(facebookToken.getSignedRequest());
            if (!facebookToken.getUserId().equals(facebookUnsignedRequest.getUserId())) {
                throw new BadCredentialException("Invalid Facebook Signed Request");
            }
        }
        // get user
        FacebookAccessToken facebookAccessToken = (FacebookAccessToken) facebookToken.readCredentials();
        JsonObject me = facebookClient.getMe(facebookAccessToken);
        facebookToken.setMe(me);
        if (facebookToken.getUserId() != null && !facebookToken.getUserId().equals(me.getString("id"))) {
            throw new BadCredentialException("Invalid Facebook Access Token for Facebook user ID " + facebookToken.getUserId() + ". Token was for Facebook user ID " + me.getString("id"));
        }
        // get local account
        Account account = getAccountRepository().findAccount(token);
        if (account == null) {
            throw new AccountNotFoundException(String.valueOf(token.getToken()));
        }
        if (account.isLocked()) {
            throw new AccountLockedException(account.getPrincipal().getName());
        }
        return new AuthenticatedSubject(
            account,
            null,
            token,
            getSessionConfigurations().getConfiguration(token.getSystem()),
            loginContext);
    }

}
