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
package com.guestful.jaxrs.security.subject;

import com.guestful.jaxrs.security.LoginContext;
import com.guestful.jaxrs.security.realm.Account;
import com.guestful.jaxrs.security.session.DefaultSession;
import com.guestful.jaxrs.security.session.Session;
import com.guestful.jaxrs.security.session.SessionConfiguration;
import com.guestful.jaxrs.security.token.AuthenticationToken;

import javax.ws.rs.container.ContainerRequestContext;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class DefaultSubject implements Subject {


    private final Account account;
    private Session session;
    private final AuthenticationToken authenticationToken;
    private final SessionConfiguration sessionConfiguration;
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();
    private final String origin;
    private final ContainerRequestContext request;

    public DefaultSubject(Account account,
                          Session session,
                          AuthenticationToken authenticationToken,
                          SessionConfiguration sessionConfiguration,
                          LoginContext loginContext) {
        this.account = account;
        this.authenticationToken = authenticationToken;
        this.session = session;
        this.sessionConfiguration = sessionConfiguration;
        this.request = loginContext.getRequest();
        this.attributes.putAll(loginContext.getAttributes());
        this.origin = loginContext.getOrigin();
    }

    @Override
    public Principal getPrincipal() {
        return account.getPrincipal();
    }

    @Override
    public Session getSession(boolean create) {
        if (session == null && create) {
            session = new DefaultSession(sessionConfiguration.getMaxAge(), getOrigin());
        }
        return session;
    }

    @Override
    public boolean isPermitted(Collection<String> permissions) {
        return account.getPermissions().containsAll(permissions);
    }

    @Override
    public boolean hasRoles(Collection<String> roles) {
        return account.getRoles().containsAll(roles);
    }

    @Override
    public ContainerRequestContext getRequest() {
        return request;
    }

    @Override
    public AuthenticationToken getAuthenticationToken() {
        return authenticationToken;
    }

    @Override
    public void setAttribute(String name, Object value) {
        attributes.put(name, value);
    }

    @Override
    public Object getAttribute(String name) {
        return attributes.get(name);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Collections.unmodifiableMap(attributes);
    }

    @Override
    public String getOrigin() {
        return origin;
    }

}
