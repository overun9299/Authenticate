package soap.controller;

import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import soap.config.JwtProperties;
import soap.utils.JwtUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by ZhangPY on 2020/3/12
 * Belong Organization OVERUN-9299
 * overun9299@163.com
 * Explain:
 */
@RestController
public class UserController {

    @Autowired
    private JwtProperties jwtProperties;


    @GetMapping(value = "/getUser")
    public String getUser(HttpServletRequest request) {
        /** 在这可以获取到，token中的信息 */
        Map<String, Object> infoFromToken = new HashMap<>();
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if ("AUTH_TOKEN".equals(cookie.getName())) {
                try {
                    infoFromToken = JwtUtils.getInfoFromToken(cookie.getValue(), this.jwtProperties.getPublicKey());
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        }

        return JSONObject.toJSONString(infoFromToken);
    }

}
