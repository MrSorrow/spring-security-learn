package guo.ping.security.core.authentic.mobile;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * @description:
 * @author: guoping wang
 * @date: 2019/6/1 16:22
 * @project: spring-security-learn
 */
public class SmsCodeAuthenticationToken extends AbstractAuthenticationToken {

    private final Object mobile;

    public SmsCodeAuthenticationToken(Object mobile) {
        super((Collection)null);
        this.mobile = mobile;
        this.setAuthenticated(false);
    }

    public SmsCodeAuthenticationToken(Object mobile, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.mobile = mobile;
        super.setAuthenticated(true);
    }

    public Object getCredentials() {
        return null;
    }

    public Object getPrincipal() {
        return this.mobile;
    }

    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        } else {
            super.setAuthenticated(false);
        }
    }

    public void eraseCredentials() {
        super.eraseCredentials();
    }
}
