package soap.service;

/**
 * Created by ZhangPY on 2020/3/11
 * Belong Organization OVERUN-9299
 * overun9299@163.com
 * Explain:
 */
public interface AuthService {

    /**
     * 认证方法
     * @param username 用户名
     * @param password 密码
     * @return
     */
    String accredit(String username, String password);
}
