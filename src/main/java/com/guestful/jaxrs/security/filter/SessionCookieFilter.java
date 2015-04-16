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
import com.guestful.jaxrs.security.session.SessionConfigurations;
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.subject.SubjectContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.NewCookie;
import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.TreeSet;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
@Priority(Priorities.HEADER_DECORATOR)
public class SessionCookieFilter implements ContainerResponseFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(SessionCookieFilter.class);
    private static final Date EXPIRED = new Date(System.currentTimeMillis() - 604800000);
    private static final String SESSION_COOKIE_EXPIRED = SessionCookieFilter.class.getName() + ".REMOVE_SESSION_COOKIE_REQUEST";

    private final SessionConfigurations sessionConfigurations;

    @Inject
    public SessionCookieFilter(SessionConfigurations sessionConfigurations) {
        this.sessionConfigurations = sessionConfigurations;
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) throws IOException {
        sessionConfigurations.forEach((system, config) -> {

            Subject subject = SubjectContext.getSubject(system);
            SessionConfiguration sessionConfiguration = sessionConfigurations.getConfiguration(system);

            if (sessionConfiguration.getCookieName() != null) {

                if (subject.getSession() != null
                    && subject.getAuthenticationToken() != null
                    && subject.getAuthenticationToken().isSessionAllowed()) {

                    LOGGER.trace("exit() {} - {} - set cookie {}={}", subject, request.getUriInfo().getRequestUri(), sessionConfiguration.getCookieName(), subject.getSession());

                    response.getHeaders().add(HttpHeaders.SET_COOKIE, new NewCookie(
                            sessionConfiguration.getCookieName(),
                            subject.getSession().getId(),
                            sessionConfiguration.getCookiePath(),
                            sessionConfiguration.getCookieDomain(),
                            null,
                            subject.getSession().getMaxAge(),
                            false,
                            true)
                    );
                }

                Cookie cookie = request.getCookies().get(sessionConfiguration.getCookieName());
                Collection<String> expired = getExpiredSystems(request);

                if (cookie != null && !response.getCookies().containsKey(cookie.getName()) && expired.contains(system)) {

                    // remove old session cookie if not authenticated anymore or if a new session has been created

                    LOGGER.trace("exit() {} - {} - remove old cookie {}", subject, request.getUriInfo().getRequestUri(), cookie.getName());

                    response.getHeaders().addFirst(HttpHeaders.SET_COOKIE, new NewCookie(
                        cookie.getName(),
                        "delete",
                        sessionConfiguration.getCookiePath(),
                        sessionConfiguration.getCookieDomain(),
                        cookie.getVersion(),
                        null,
                        0,
                        EXPIRED,
                        false,
                        true));
                    expired.remove(system);
                }
            }
        });
    }

    @SuppressWarnings("unchecked")
    public static Collection<String> getExpiredSystems(ContainerRequestContext request) {
        Collection<String> expired = (Set<String>) request.getProperty(SESSION_COOKIE_EXPIRED);
        if (expired == null) {
            expired = new TreeSet<>();
            request.setProperty(SESSION_COOKIE_EXPIRED, expired);
        }
        return expired;
    }

}
