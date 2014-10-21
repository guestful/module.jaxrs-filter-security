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
package com.guestful.jaxrs.security.filter;

import com.guestful.jaxrs.security.session.SessionConfiguration;
import com.guestful.jaxrs.security.subject.SubjectContext;
import com.guestful.jaxrs.security.token.HttpCookieToken;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.security.auth.login.LoginException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Cookie;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
@Priority(Priorities.AUTHENTICATION + 122)
public class HttpCookieAuthenticationFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = Logger.getLogger(HttpCookieAuthenticationFilter.class.getName());

    private final SessionConfiguration sessionConfiguration;

    @Inject
    public HttpCookieAuthenticationFilter(SessionConfiguration sessionConfiguration) {
        this.sessionConfiguration = sessionConfiguration;
    }

    @Override
    public void filter(ContainerRequestContext request) throws IOException {
        if (sessionConfiguration != null && sessionConfiguration.getCookieName() != null && request.getSecurityContext().getUserPrincipal() == null) {
            Cookie cookie = request.getCookies().get(sessionConfiguration.getCookieName());
            if (cookie != null) {
                LOGGER.finest("enter() " + request.getSecurityContext().getUserPrincipal() + " - " + request.getUriInfo().getRequestUri());
                HttpCookieToken token = new HttpCookieToken(cookie);
                try {
                    SubjectContext.login(token);
                } catch (LoginException e) {
                    LOGGER.log(Level.FINEST, "login failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                    request.setProperty(SessionCookieFilter.SESSION_COOKIE_EXPIRED, true);
                }
            }
        }
    }

}
