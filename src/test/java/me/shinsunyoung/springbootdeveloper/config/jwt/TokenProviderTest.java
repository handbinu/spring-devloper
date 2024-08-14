package me.shinsunyoung.springbootdeveloper.config.jwt;

import io.jsonwebtoken.Jwts;
import me.shinsunyoung.springbootdeveloper.domain.User;
import me.shinsunyoung.springbootdeveloper.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class TokenProviderTest {
    @Autowired
    private TokenProvider tokenProvider;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JwtProperties jwtProperties;

    //genarateToken() 검증 테스트
    @DisplayName("generateToken(): 유저 정보의 만료 기간을 전달해 토큰을 만들 수 있다.")
    @Test
    void generateToken(){
        //given 토큰에 유저 정보를 추가하기 위한 테스트 유저를 만듬
        User testUser = userRepository.save(User.builder()
                .email("user@gmail.com")
                .password("test")
                .build());

        // when 메서드 호출+토큰 만들기
        String token = tokenProvider.generateToken(testUser, Duration.ofDays(14));

        //then jjwt 라이브러리를 사용해 토큰 복호화
        //토큰 만들 때 클레임으로 넣어둔 id값이 given절에서 만든 유저id와 동일한지 확인
        Long userId = Jwts.parser()
                .setSigningKey(jwtProperties.getSecretKey())
                .parseClaimsJws(token)
                .getBody()
                .get("id", Long.class);

        assertThat(userId).isEqualTo(testUser.getId());
    }

    // validToken()검증 테스트
    @DisplayName("validToken(): 만료된 토큰인 때에 유효성 검증에 실패한다")
    @Test
    void vailToken_invalidToken(){
        //given 토큰 생성, 만료된 토큰으로 설정
        String token = JwtFactory.builder()
                .expiration(new Date(new Date().getTime() - Duration.ofDays(7).toMillis()))
                .build()
                .createToken(jwtProperties);

        //when  유효한 토큰인지 검증
        boolean result = tokenProvider.validToken(token);

        //then
        assertThat(result).isFalse();
    }

    @DisplayName("validToken(): 만료된 토큰인 때에 유효성 검증에 실패한다")
    @Test
    void vailToken_validToken(){
        //given 토큰 생성, 만료되지 않은 토큰
        String token = JwtFactory.withDefaultValues().createToken(jwtProperties);

        //when
        boolean result = tokenProvider.validToken(token);

        //then
        assertThat(result).isTrue();
    }

    //getAuthentication() 검정 테스트
    @DisplayName("getAuthentication(): 토큰 기반으로 인증 정보를 가져올 수 있다.")
    @Test
    void getAuthentication() {
        //given 토큰 제목으로 subject 지정
        String userEmail = "user@email.com";
        String token = JwtFactory.builder()
                .subject(userEmail)
                .build()
                .createToken(jwtProperties);

        //when
        Authentication authentication = tokenProvider.getAuthentication(token);

        //then
        assertThat(((UserDetails) authentication.getPrincipal()).getUsername())
                .isEqualTo(userEmail);
    }

    //getUserId() 검증 테스트
    @DisplayName("getUserId(): 토큰으로 유저 ID를 가져올 수 있다.")
    @Test
    void getUserId(){
        //given 토큰 생성, 클레임 추가, "id" 키 , 값은 1인 유저아이디
        Long userId = 1L;
        String token = JwtFactory.builder()
                .claims(Map.of("id", userId))
                .build()
                .createToken(jwtProperties);

        //when
        Long userIdByToken = tokenProvider.getUserId(token);

        //then
        assertThat(userIdByToken).isEqualTo(userId);
    }
}
