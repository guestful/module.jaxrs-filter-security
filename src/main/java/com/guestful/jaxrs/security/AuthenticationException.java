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
package com.guestful.jaxrs.security;

import com.guestful.jaxrs.security.annotation.AuthScheme;

import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.UriInfo;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class AuthenticationException extends NotAuthorizedException {

    public AuthenticationException(String message, ContainerRequestContext request) {
        this(message, AuthScheme.BASICAUTH, request);
    }

    public AuthenticationException(String message, AuthScheme scheme, ContainerRequestContext request) {
        this(message, scheme, request.getUriInfo());
    }

    public AuthenticationException(String message, UriInfo uriInfo) {
        this(message, AuthScheme.BASICAUTH, uriInfo);
    }

    public AuthenticationException(String message, AuthScheme scheme, UriInfo uriInfo) {
        super(message, scheme + " realm=\"" + uriInfo.getBaseUri() + "\"");
    }

    public AuthenticationException(String message, Throwable cause, ContainerRequestContext request) {
        super(message, cause, AuthScheme.BASICAUTH + " realm=\"" + request.getUriInfo().getBaseUri() + "\"");
    }
}
