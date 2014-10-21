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

import com.guestful.jaxrs.security.AuthenticationException;
import com.guestful.jaxrs.security.annotation.AuthScheme;
import com.guestful.jaxrs.security.subject.SubjectContext;
import com.guestful.jaxrs.security.token.AuthenticationToken;
import com.guestful.jaxrs.security.token.HttpBasicToken;

import javax.annotation.Priority;
import javax.security.auth.login.LoginException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.logging.Logger;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
@Priority(Priorities.AUTHENTICATION + 121)
public class HttpBasicAuthenticationFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = Logger.getLogger(HttpBasicAuthenticationFilter.class.getName());

    /**
     * HTTP Authorization header, equal to <code>Authorization</code>
     */
    private static final String AUTHORIZATION_HEADER = "Authorization";

    @Override
    public void filter(ContainerRequestContext request) throws IOException {
        if (request.getSecurityContext().getUserPrincipal() == null) {
            String authzHeader = request.getHeaders().getFirst(AUTHORIZATION_HEADER);
            if (authzHeader != null) {
                LOGGER.finest("enter() " + request.getSecurityContext().getUserPrincipal() + " - " + request.getUriInfo().getRequestUri());
                AuthScheme authScheme = AuthScheme.fromHeader(authzHeader.toUpperCase(Locale.ENGLISH));
                if (authScheme != AuthScheme.BASIC && authScheme != AuthScheme.BASICAUTH) {
                    throw new AuthenticationException("Unsupported scheme", request);
                }
                String[] parts = authzHeader.split(" ");
                if (parts.length < 2) {
                    throw new AuthenticationException("Malformed Basic HTTP Authorization", request);
                }
                String userInfo = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
                parts = userInfo.split(":", 2);
                if (parts.length < 2) {
                    throw new AuthenticationException("Malformed Basic HTTP Authorization", request);
                }
                AuthenticationToken token = new HttpBasicToken(authScheme, parts[0], parts[1]);
                try {
                    SubjectContext.login(token);
                } catch (LoginException e) {
                    throw new AuthenticationException(e.getMessage(), e, request);
                }
            }
        }
    }

}
