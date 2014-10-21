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

import com.guestful.jaxrs.security.SecurityService;
import com.guestful.jaxrs.security.token.AuthenticationToken;

import javax.security.auth.login.LoginException;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class SubjectContext {

    private static SecurityService SERVICE;

    private static SecurityService getSecurityService() {
        if (SERVICE == null) {
            throw new IllegalStateException("No " + SecurityService.class.getSimpleName() + " set");
        }
        return SERVICE;
    }

    private static final ThreadLocal<Subject> SUBJECT = new ThreadLocal<>();

    static void logout(Subject subject) {
        if (subject == null) throw new NullPointerException();
        getSecurityService().logout(subject);
        if (getSubject(false) == subject) {
            clearCurrentSubject();
        }
    }

    public static void setSecurityService(SecurityService securityService) {
        if (SERVICE != null) {
            throw new IllegalStateException(SecurityService.class.getSimpleName() + " already set");
        }
        SERVICE = securityService;
    }

    public static Subject login(AuthenticationToken token) throws LoginException {
        if (token == null) throw new NullPointerException();
        Subject current = getSubject();
        Subject subject = getSecurityService().login(token, current);
        setCurrentSubject(subject);
        return subject;
    }

    public static Subject getSubject() {
        return getSubject(true);
    }

    public static Subject getSubject(boolean createAnonymousIfNone) {
        Subject subject = SUBJECT.get();
        if (subject == null && createAnonymousIfNone) {
            subject = new AnonymousSubject();
        }
        return subject;
    }

    public static void setCurrentSubject(Subject subject) {
        if (subject == null) throw new NullPointerException();
        if (subject instanceof AnonymousSubject) throw new IllegalArgumentException();
        SUBJECT.set(subject);
    }

    public static void clearCurrentSubject() {
        Subject current = getSubject(false);
        if (current != null) {
            SUBJECT.remove();
        }
    }

    public static void accessed(Subject subject) {
        if (subject == null) throw new NullPointerException();
        getSecurityService().accessed(subject);
    }
}
