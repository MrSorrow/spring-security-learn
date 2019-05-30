package guo.ping.security.core.validate.code;

import org.springframework.security.core.AuthenticationException;

/**
 * @description:
 * @author: guoping wang
 * @date: 2019/5/31 1:10
 * @project: spring-security-learn
 */
public class ValidateCodeException extends AuthenticationException {

    public ValidateCodeException(String msg) {
        super(msg);
    }

}
