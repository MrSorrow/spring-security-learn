package guo.ping.security.browser.session;

import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.ServletException;
import java.io.IOException;

/**
 * @description:
 * @author: guoping wang
 * @date: 2019/6/1 21:11
 * @project: spring-security-learn
 */
public class MyExpiredSessionStrategy implements SessionInformationExpiredStrategy {

    // SessionInformationExpiredEvent表示Session过期
    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent sessionInformationExpiredEvent) throws IOException, ServletException {
        // do sth.
    }
}
