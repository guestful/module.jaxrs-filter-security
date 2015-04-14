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

import com.guestful.jaxrs.security.session.SessionConfiguration;
import com.guestful.jaxrs.security.session.SessionConfigurations;
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.subject.SubjectSecurityContext;

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
import java.util.logging.Logger;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
@Priority(Priorities.HEADER_DECORATOR)
public class SessionCookieFilter implements ContainerResponseFilter {

    private static final Logger LOGGER = Logger.getLogger(SessionCookieFilter.class.getName());
    private static final Date EXPIRED = new Date(System.currentTimeMillis() - 604800000);
    public static final String SESSION_COOKIE_EXPIRED = SessionCookieFilter.class.getName() + ".REMOVE_SESSION_COOKIE_REQUEST";

    private final SessionConfigurations sessionConfigurations;

    @Inject
    public SessionCookieFilter(SessionConfigurations sessionConfigurations) {
        this.sessionConfigurations = sessionConfigurations;
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) throws IOException {
        SubjectSecurityContext subjectSecurityContext = (SubjectSecurityContext) request.getSecurityContext();
        sessionConfigurations.forEach((system, config) -> {
            SessionConfiguration sessionConfiguration = sessionConfigurations.getConfiguration(system);
            if (sessionConfiguration.getCookieName() != null) {
                LOGGER.finest("exit() " + subjectSecurityContext.getUserPrincipal(system) + " - " + request.getUriInfo().getRequestUri());
                Subject subject = subjectSecurityContext.getSubject(system);

                if (subject.getSession() != null
                    && subject.getAuthenticationToken() != null
                    && subject.getAuthenticationToken().isSessionAllowed()) {
                    LOGGER.finest("exit() set cookie: " + sessionConfiguration.getCookieName() + "=" + subject.getSession().getId());
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
                Collection<String> expired = (Set<String>) request.getProperty(SESSION_COOKIE_EXPIRED);
                if (cookie != null && !response.getCookies().containsKey(cookie.getName()) && expired != null && expired.contains(system)) {
                    // remove old session cookie if not authenticated anymore or if a new session has been created
                    LOGGER.finest("exit() remove old cookie: " + cookie.getName() + "=" + cookie.getValue());
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

}
