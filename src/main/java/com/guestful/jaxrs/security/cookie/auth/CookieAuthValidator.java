package com.guestful.jaxrs.security.cookie.auth;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public interface CookieAuthValidator {
    void auth(String principal);
}
