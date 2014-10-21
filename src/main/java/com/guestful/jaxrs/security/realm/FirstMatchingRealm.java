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
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.token.AuthenticationToken;

import javax.security.auth.login.LoginException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class FirstMatchingRealm implements Realm {

    private final Collection<Realm> realms = new ArrayList<>();

    public FirstMatchingRealm(Realm... realms) {
        this.realms.addAll(Arrays.asList(realms));
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        for (Realm realm : realms) {
            if (realm.supports(token)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Subject authenticate(AuthenticationToken token, LoginContext loginContext) throws LoginException {
        for (Realm realm : realms) {
            if (realm.supports(token)) {
                return realm.authenticate(token, loginContext);
            }
        }
        throw new UnsupportedTokenException(token.getClass().getName());
    }

    @Override
    public void onLogout(Subject subject) {
        for (Realm realm : realms) {
            if (realm.supports(subject.getAuthenticationToken())) {
                realm.onLogout(subject);
                return;
            }
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " (" + String.join(",", (Iterable<String>) realms.stream().map(r -> r.getClass().getSimpleName())::iterator) + ")";
    }

}
