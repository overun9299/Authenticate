package soap.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import soap.config.JwtProperties;
import soap.service.AuthService;
import soap.utils.JwtUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by ZhangPY on 2020/3/11
 * Belong Organization OVERUN-9299
 * overun9299@163.com
 * Explain:
 */
@Slf4j
@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private JwtProperties jwtProperties;

    @Override
    public String accredit(String username, String password) {
        /** 调用数据库，或者用户服务，来验证username和password是否匹配且正确。 ps：此处先写死数据 */
        boolean isLegal = false;
        if ("soap".equals(username) && "soap".equals(password)) {
            isLegal = true;
        } else if ("adm".equals(username) && "adm".equals(password)) {
            isLegal = true;
        }
        if (isLegal) {
            /** 生成token */
            Map<String , Object> result = new HashMap<>();
            result.put("name" , username);
            try {
                return JwtUtils.generateToken(result, jwtProperties.getPrivateKey(), jwtProperties.getExpire());
            } catch (Exception e) {
                log.error(e.getMessage());
            }

        }
        return null;
    }
}
