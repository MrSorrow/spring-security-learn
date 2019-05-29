package guo.ping.security.core.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @description:
 * @author: guoping wang
 * @date: 2019/5/29 20:57
 * @project: spring-security-learn
 */
@ConfigurationProperties(prefix = "my.security")
public class SecurityProperties {

    private BrowserProperties browser = new BrowserProperties();

    public BrowserProperties getBrowser() {
        return browser;
    }

    public void setBrowser(BrowserProperties browser) {
        this.browser = browser;
    }
}
