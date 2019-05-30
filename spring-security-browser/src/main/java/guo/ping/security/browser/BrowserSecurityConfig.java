package guo.ping.security.browser;

import guo.ping.security.core.properties.SecurityProperties;
import guo.ping.security.core.validate.code.ValidateCodeFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @description:
 * @author: guoping wang
 * @date: 2019/5/28 20:34
 * @project: spring-security-learn
 */
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SecurityProperties securityProperties;

    @Autowired
    private AuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler myAuthenticationFailureHandler;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ValidateCodeFilter validateCodeFilter = new ValidateCodeFilter();
        validateCodeFilter.setMyAuthenticationFailureHandler(myAuthenticationFailureHandler);

//        http.httpBasic() // 所有的请求都需要弹框式表单登录进行认证
        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class)
            .formLogin() // 所有的请求都需要表单登录进行认证
            .loginPage("/user/login")  // 指定登录页
            .loginProcessingUrl("/user/authentication") // 指定登录表单信息提交处理请求，和登录页中的需一致
            .successHandler(myAuthenticationSuccessHandler)
            .failureHandler(myAuthenticationFailureHandler)
            .and()
            .authorizeRequests()  // 对请求进行授权
            .antMatchers("/user/login", securityProperties.getBrowser().getLoginPage(), "/code/image").permitAll() // 登录页无需认证
            .anyRequest()  // 对任何请求
            .authenticated()  // 进行授权
            .and()
            .csrf().disable(); // 屏蔽跨站请求伪造
    }
}
