package kea.dpang.gateway.jwt;

import io.jsonwebtoken.*;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;

@Component
@Slf4j
public class JwtTokenProvider {

    @Value("${token.secret}")
    private String SECRET;

    private byte[] key;

    private Claims getClaimsFromJwtToken(String token) {
        this.key = Base64.getDecoder().decode(SECRET);
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            log.error("Jwt Body 파싱 에러: ",e);
            return e.getClaims();
        }
    }

    public String getUserId(String token) {
        return getClaimsFromJwtToken(token).get("client-id",String.class);
    }

    public List<String> getRoles(String token) {
        return (List<String>) getClaimsFromJwtToken(token).get("role");
    }

    public void validateJwtToken(String token) {
        this.key = Base64.getDecoder().decode(SECRET);
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
        }
        catch (SignatureException  | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException | ExpiredJwtException
                jwtException
        ) {
            log.error("JWT 파싱 에러: ",jwtException);
            throw jwtException;
        }
    }

}