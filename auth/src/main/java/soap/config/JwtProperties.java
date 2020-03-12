package soap.config;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import soap.utils.RsaUtils;

import javax.annotation.PostConstruct;
import java.io.File;
import java.security.PrivateKey;
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

    /** 密钥 */
    private String secret;

    /** 公钥文件地址 */
    private String pubKeyPath;

    /** 私钥文件地址 */
    private String priKeyPath;

    /** token过期时间 */
    private int expire;

    /** cookie名称 */
    private String cookieName;

    /** cookie名称 */
    private PublicKey publicKey;

    /** 私钥 */
    private PrivateKey privateKey;


    /**
     * 在构造方法执行之后执行该方法
     */
    @PostConstruct
    public void init() {
        try {
            File pubKey = new File(pubKeyPath);
            File priKey = new File(priKeyPath);
            if (!pubKey.exists() || !priKey.exists()) {
                // 生成公钥和私钥
                RsaUtils.generateKey(pubKeyPath, priKeyPath, secret);
            }
            // 获取公钥和私钥
            this.publicKey = RsaUtils.getPublicKey(pubKeyPath);
            this.privateKey = RsaUtils.getPrivateKey(priKeyPath);
        } catch (Exception e) {
            log.error("初始化公钥和私钥失败！", e);
            throw new RuntimeException();
        }
    }
}
