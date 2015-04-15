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
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.subject.SubjectContext;
import com.guestful.jaxrs.security.token.HttpCookieToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.security.auth.login.LoginException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Cookie;
import java.io.IOException;
import java.util.Collection;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
@Priority(Priorities.AUTHENTICATION + 122)
public class HttpCookieAuthenticationFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpCookieAuthenticationFilter.class);

    private final SessionConfigurations sessionConfigurations;

    @Inject
    public HttpCookieAuthenticationFilter(SessionConfigurations sessionConfigurations) {
        this.sessionConfigurations = sessionConfigurations;
    }

    @Override
    public void filter(ContainerRequestContext request) throws IOException {
        Collection<String> expired = SessionCookieFilter.getExpiredSystems(request);
        sessionConfigurations.forEach((system, config) -> {
            Subject subject = SubjectContext.getSubject(system);
            if (config.getCookieName() != null && subject.getPrincipal() == null) {
                Cookie cookie = request.getCookies().get(config.getCookieName());
                if (cookie != null) {
                    LOGGER.trace("enter() {} - {}", subject, request.getUriInfo().getRequestUri());
                    HttpCookieToken token = new HttpCookieToken(system, cookie);
                    try {
                        SubjectContext.login(token);
                    } catch (LoginException e) {
                        LOGGER.trace("login failed: {}: {}", e.getClass().getSimpleName(), e.getMessage());
                        expired.add(system);
                    }
                }
            }
        });
    }

}
