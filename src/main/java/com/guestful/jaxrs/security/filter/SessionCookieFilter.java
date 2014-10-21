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
import javax.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.util.Date;
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

    private final SessionConfiguration sessionConfiguration;

    @Inject
    public SessionCookieFilter(SessionConfiguration sessionConfiguration) {
        this.sessionConfiguration = sessionConfiguration;
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) throws IOException {
        SecurityContext context = request.getSecurityContext();
        if (sessionConfiguration.getCookieName() != null && context instanceof SubjectSecurityContext) {
            LOGGER.finest("exit() " + context.getUserPrincipal() + " - " + request.getUriInfo().getRequestUri());
            Subject subject = ((SubjectSecurityContext) context).getSubject();

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
            if (cookie != null && !response.getCookies().containsKey(cookie.getName()) && request.getProperty(SESSION_COOKIE_EXPIRED) != null) {
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
                request.removeProperty(SESSION_COOKIE_EXPIRED);
            }
        }
    }

}
