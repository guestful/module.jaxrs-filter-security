package com.guestful.jaxrs.security.cookie.auth;

import java.security.Principal;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class NamedPrincipal implements Principal {

    private final String name;

    public NamedPrincipal(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return getName();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NamedPrincipal that = (NamedPrincipal) o;
        return !(name != null ? !name.equals(that.name) : that.name != null);
    }

    @Override
    public int hashCode() {
        return name != null ? name.hashCode() : 0;
    }
}
