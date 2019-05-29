package guo.ping.security.browser.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @description:
 * @author: guoping wang
 * @date: 2019/5/29 15:36
 * @project: spring-security-learn
 */
@Component
public class MyUserDetailsService implements UserDetailsService {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * 模拟从数据库中依据username查询具体的用户信息
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        logger.info("start query user info from db by username = " + username);
        String password = bCryptPasswordEncoder.encode("123456");
        logger.info("query user password = " + password);

        // 这个User对象时Spring中提供的，已经实现了UserDetails接口，UserDetails接口包含了用户的名称、密码、密码是否过期、账户是否冻结、是否删除、所拥有的权限等信息
        return new User(username, password, true,true,true,true, AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
