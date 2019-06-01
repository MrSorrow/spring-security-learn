package guo.ping.security.core.authentic.mobile;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @description:
 * @author: guoping wang
 * @date: 2019/6/1 16:34
 * @project: spring-security-learn
 */
public class SmsCodeAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;

    public UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        SmsCodeAuthenticationToken smsCodeAuthenticationToken = (SmsCodeAuthenticationToken) authentication;
        UserDetails userDetails = userDetailsService.loadUserByUsername((String) smsCodeAuthenticationToken.getPrincipal());

        if (userDetails == null) {
            throw new InternalAuthenticationServiceException("无法获取用户信息");
        }

        // 构建认证后的SmsCodeAuthenticationToken
        SmsCodeAuthenticationToken authenticationToken = new SmsCodeAuthenticationToken(userDetails, userDetails.getAuthorities());
        authenticationToken.setDetails(smsCodeAuthenticationToken.getDetails());
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        // 判断传递的aClass是否是SmsCodeAuthenticationToken类型
        return SmsCodeAuthenticationToken.class.isAssignableFrom(aClass);
    }
}
