package soap.config;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import soap.utils.RsaUtils;

import javax.annotation.PostConstruct;
import java.security.PublicKey;

/**
 * Created by ZhangPY on 2020/3/11
 * Belong Organization OVERUN-9299
 * overun9299@163.com
 * Explain:
 */
@Slf4j
@Data
@Component
@ConfigurationProperties(prefix = "auth.jwt")
public class JwtProperties {

    /** 公钥文件地址 */
    private String pubKeyPath;

    /** cookie名称 */
    private String cookieName;

    /** 公钥 */
    private PublicKey publicKey;


    /**
     * 在构造方法执行之后执行该方法
     */
    @PostConstruct
    public void init() {
        try {
            /** 获取公钥 */
            this.publicKey = RsaUtils.getPublicKey(pubKeyPath);
        } catch (Exception e) {
            log.error("初始化公钥失败！", e);
            throw new RuntimeException();
        }
    }
}
