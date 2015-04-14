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
package com.guestful.jaxrs.security.filter;

import com.guestful.jaxrs.security.session.SessionConfigurations;
import com.guestful.jaxrs.security.subject.SubjectContext;
import com.guestful.jaxrs.security.subject.SubjectSecurityContext;
import com.guestful.jaxrs.security.token.HttpCookieToken;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.security.auth.login.LoginException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Cookie;
import java.io.IOException;
import java.util.Collection;
import java.util.TreeSet;
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

    private final SessionConfigurations sessionConfigurations;

    @Inject
    public HttpCookieAuthenticationFilter(SessionConfigurations sessionConfigurations) {
        this.sessionConfigurations = sessionConfigurations;
    }

    @Override
    public void filter(ContainerRequestContext request) throws IOException {
        SubjectSecurityContext subjectSecurityContext = (SubjectSecurityContext) request.getSecurityContext();
        Collection<String> expired = new TreeSet<>();
        sessionConfigurations.forEach((system, config) -> {
            if (config.getCookieName() != null && subjectSecurityContext.getUserPrincipal(system) == null) {
                Cookie cookie = request.getCookies().get(config.getCookieName());
                if (cookie != null) {
                    LOGGER.finest("enter() " + subjectSecurityContext.getUserPrincipal(system) + " - " + request.getUriInfo().getRequestUri());
                    HttpCookieToken token = new HttpCookieToken(system, cookie);
                    try {
                        SubjectContext.login(token);
                    } catch (LoginException e) {
                        LOGGER.log(Level.FINEST, "login failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                        expired.add(system);
                    }
                }
            }
        });
        if (!expired.isEmpty()) {
            request.setProperty(SessionCookieFilter.SESSION_COOKIE_EXPIRED, expired);
        }
    }

}
