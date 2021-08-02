package knut.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import knut.domain.Member;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@Slf4j
public class jwtTokenProvider {

    private String secretCode = "made_in_gyu0";
    private final String secretKey;
    private final Long tokenValidityMilliSeconds;

    private Key key;

    public jwtTokenProvider(
            @Value("${jwt.token-validity-in-seconds}") Long tokenValiditySecond) {
        this.tokenValidityMilliSeconds = tokenValiditySecond * 1000;                    // 유효시간 꺼내오기
        this.secretKey = Base64.getEncoder().encodeToString(secretCode.getBytes());     // 암호와 키
    }

    @PostConstruct
    public void init(){
        byte[] decode = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(decode);
    }


    // 토큰 생성 ============================================================
    public String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        log.info("{}/{}/{}",authorities,authentication.getAuthorities(),authentication.getName());

        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenValidityMilliSeconds);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim("knut_auth", authorities)      // 비공개 클레임을 설정할 수 있습니다. (key-value)
                .signWith(key, SignatureAlgorithm.HS512)    // 해싱 알고리즘과 시크릿 키를 설정할 수 있습니다.
                .setExpiration(validity)                    // 만료 시간(exp)을 설정할 수 있습니다.
                .compact();
    }

            /*
               return Jwts.builder()
                        .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                        .setIssuer("fresh")
                        .setIssuedAt(now)
                        .setExpiration(new Date(now.getTime() + Duration.ofMinutes(30).toMillis()))
                        .claim("id", "아이디")
                        .claim("email", "a@gmail.com")
                        .signWith(SignatureAlgorithm.HS256, "secret") // (6)
                     .compact();

              헤더의 타입(typ)을 지정할 수 있습니다. jwt를 사용하기 때문에 Header.JWT_TYPE로 사용해줍니다.
              등록된 클레임 중, 토큰 발급자(iss)를 설정할 수 있습니다.
              등록된 클레임 중, 발급 시간(iat)를 설정할 수 있습니다. Date 타입만 추가가 가능합니다.
              등록된 클레임 중, 만료 시간(exp)을 설정할 수 있습니다. 마찬가지로 Date 타입만 추가가 가능합니다.
              비공개 클레임을 설정할 수 있습니다. (key-value)
              해싱 알고리즘과 시크릿 키를 설정할 수 있습니다.
              모든 설정이 끝나면 compact()를 통해 JWT 토큰을 만들 수 있습니다.
             */

    // 토큰 얻기 ============================================================
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("knut_auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), " ", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    // 유효성 검사 ============================================================
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            // .setSigningKey(key) -> 시크릿 키를 넣어주어 토큰을 해석할 수 있습니다.
            // .build() -> 스레드에 안전한 JwtPaser를 리턴하기 위해 JwtPaserBuilder의 build()메서드를 호출한다.
            // .getBody()를 호출하게 되면, Claim 타입의 결과 객체를 반환하게 되는데, 여기에서 저장된 클레임 정보들을 확인할 수 있습니다.
            // .parseClaimsJws(token) -> 마지막으로 원본 JWS를 생성하는 jws를 가지고 parseClaimsJws(String)메서드를 호출한다.
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
//        UnsupportedJwtException : 예상하는 형식과 다른 형식이거나 구성의 JWT일 때
//        MalformedJwtException : JWT가 올바르게 구성되지 않았을 때
//        ExpiredJwtException : JWT를 생성할 때 지정한 유효기간이 초과되었을 때
//        SignatureException : JWT의 기존 서명을 확인하지 못했을 때
//        IllegalArgumentException
        return false;
    }
}
