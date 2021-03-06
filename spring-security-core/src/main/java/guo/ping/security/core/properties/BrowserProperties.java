/**
 *
 */
package guo.ping.security.core.properties;

/**
 * @author zhailiang
 */
public class BrowserProperties {

    private String loginPage = "/signIn.html";
    private LoginType loginType = LoginType.JSON;
    private Integer rememberMeSeconds = 3600;

    public Integer getRememberMeSeconds() {
        return rememberMeSeconds;
    }

    public void setRememberMeSeconds(Integer rememberMeSeconds) {
        this.rememberMeSeconds = rememberMeSeconds;
    }

    public String getLoginPage() {
        return loginPage;
    }

    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }

    public LoginType getLoginType() {
        return loginType;
    }

    public void setLoginType(LoginType loginType) {
        this.loginType = loginType;
    }
}
