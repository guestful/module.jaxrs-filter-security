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
package com.guestful.jaxrs.security.subject;

import com.guestful.jaxrs.security.session.DefaultSession;
import com.guestful.jaxrs.security.session.Session;
import com.guestful.jaxrs.security.token.AuthenticationToken;
import com.guestful.jaxrs.security.token.DelegatingAuthenticationToken;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.SecurityContext;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class DelegatingSubject implements Subject {

    private final Map<String, Object> attributes = new ConcurrentHashMap<>();
    private final ContainerRequestContext request;
    private final SecurityContext securityContext;
    private final AuthenticationToken authenticationToken;
    private final String system;
    private Session session;

    public DelegatingSubject(ContainerRequestContext request) {
        this("", request);
    }

    public DelegatingSubject(String system, ContainerRequestContext request) {
        this.system = system;
        this.request = request;
        this.securityContext = request.getSecurityContext();
        this.authenticationToken = new DelegatingAuthenticationToken(securityContext);
    }

    @Override
    public String getSystem() {
        return system;
    }

    @Override
    public Principal getPrincipal() {
        return securityContext.getUserPrincipal();
    }

    @Override
    public Session getSession(boolean create) {
        if (session == null && create) {
            session = new DefaultSession();
        }
        return session;
    }

    @Override
    public boolean hasRoles(Collection<String> roles) {
        for (String role : roles) {
            if (!securityContext.isUserInRole(role)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean isPermitted(Collection<String> permissions) {
        return false;
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
        return request.getHeaderString("X-Forwarded-For");
    }

    @Override
    public String getUserAgent() {
        return request.getHeaderString(HttpHeaders.USER_AGENT);
    }

    @Override
    public String toString() {
        return system + ":" + (getPrincipal() == null ? "<anonymous>" : getPrincipal().getName());
    }

}
