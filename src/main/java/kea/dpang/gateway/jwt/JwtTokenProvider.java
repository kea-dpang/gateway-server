package kea.dpang.gateway.jwt;

import io.jsonwebtoken.*;

import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.List;

@Component
@Slf4j
public class JwtTokenProvider implements InitializingBean {
    private final String SECRET;
    private Key key;

    public JwtTokenProvider(
            @Value("${token.secret}") String secret
    ){
        this.SECRET = secret;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(SECRET);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    private Claims getClaimsFromJwtToken(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            log.error("Jwt Body 파싱 에러: ",e);
            return e.getClaims();
        }
    }

    public Long getUserId(String token) {
        return getClaimsFromJwtToken(token).get("client-id",Long.class);
    }

    public String getRoles(String token) {
        return getClaimsFromJwtToken(token).get("role",String.class);
    }

    public void validateJwtToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
        } catch (SignatureException e)
        {
            log.error("JWT 서명 검증 에러: ",e);
            throw e;
        } catch (MalformedJwtException e){
            log.error("JWT 형식 에러: ",e);
            throw e;
        } catch (UnsupportedJwtException e){
            log.error("JWT 미지원 형식 에러: ",e);
            throw e;
        } catch (IllegalArgumentException e){
            log.error("JWT 인수값 에러: ");
            throw e;
        } catch (ExpiredJwtException e){
            log.error("JWT 만료 에러: ");
            throw e;
        }
    }
}