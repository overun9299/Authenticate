package soap.controller;


import com.alibaba.fastjson.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import soap.config.JwtProperties;
import soap.service.AuthService;
import soap.utils.CookieUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by ZhangPY on 2020/3/11
 * Belong Organization OVERUN-9299
 * overun9299@163.com
 * Explain:
 */
@RestController
@RequestMapping(value = "/auth")
public class AuthController {

    @Autowired
    private JwtProperties jwtProperties;

    @Autowired
    private AuthService authService;

    /**
     * 认证方法
     * @param username 用户名
     * @param password 密码
     * @param request
     * @param response
     * @return
     */
    @PostMapping(value = "/accredit")
    public String accredit(@RequestParam("username") String username, @RequestParam("password") String password, HttpServletRequest request, HttpServletResponse response) {
        Map<String , Object> result = new HashMap<>();
        if (StringUtils.isBlank(username) || StringUtils.isBlank(password)) {
            result.put("success" , false);
            result.put("msg" , "用户名或密码不能为空！");
        } else {
            String token = authService.accredit(username , password);
            if (StringUtils.isNotBlank(token)) {
                /** 将token写入cookie */
                CookieUtils.setCookie(request, response, jwtProperties.getCookieName(), token, jwtProperties.getExpire() * 60);
                result.put("success" , true);
                result.put("msg" , "登陆成功");
            } else {
                result.put("success" , false);
                result.put("msg" , "登录失败，用户名或密码错误");
            }
        }
        return JSONObject.toJSONString(result);
    }

}
