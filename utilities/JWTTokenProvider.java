package shehan.auth.authserver.utilities;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import shehan.auth.authserver.constants.SecurityConstant;
import shehan.auth.authserver.domain.UserPrincipal;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

@Component
public class JWTTokenProvider {
    @Value("jwt.secret")
    private String secret;

    public String generateJWTToken(UserPrincipal userPrincipal){
        String [] claims = getClaimsFromUser(userPrincipal);
        return JWT.create().withIssuer(SecurityConstant.GET_ARRAYS_LLC).withAudience(SecurityConstant.GET_ARRAYS_ADMINISTRATOR)
                .withIssuedAt(new Date()).withSubject(userPrincipal.getUsername())
                .withArrayClaim(SecurityConstant.AUTHORITIES, claims)
                .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstant.EXPIRATION_TIME) )
                .sign(Algorithm.HMAC512(secret.getBytes()));

    }

    public List<GrantedAuthority> getAuthotities(String token){
        String[] claims = getClaimsFromToken(token);
        return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());

    }

    public Authentication getAuthentication(String username, List<GrantedAuthority> authorities, HttpServletRequest request){
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return usernamePasswordAuthenticationToken;
    }

    public String getSubject(String token){
        JWTVerifier verifier = getJWTVerifier();
        return verifier.verify(token).getSubject();
    }

    public boolean isTokenValid(String username,String token){
        JWTVerifier jwtVerifier = getJWTVerifier();
        return StringUtils.isNotEmpty(username) && isTokenExpired(jwtVerifier,token);
    }

    private boolean isTokenExpired(JWTVerifier verifier , String token){
        Date expirationDate = verifier.verify(token).getExpiresAt();
        return expirationDate.before(new Date());
    }


    private String[] getClaimsFromToken(String token){
        JWTVerifier jwtVerifier = getJWTVerifier();
        return jwtVerifier.verify(token).getClaim(SecurityConstant.AUTHORITIES).asArray(String.class);
    }


    private JWTVerifier getJWTVerifier(){
        JWTVerifier jwtVerifier;
        Algorithm algorithm = Algorithm.HMAC512(secret);
        try{
            jwtVerifier = JWT.require(algorithm).withIssuer(SecurityConstant.GET_ARRAYS_LLC).build();
        }catch (JWTVerificationException e){
            throw new JWTVerificationException(SecurityConstant.TOKEN_CAN_NOT_BE_VARIFIED);
        }
        return jwtVerifier;

    }

    private String[] getClaimsFromUser(UserPrincipal userPrincipal){
        List<String> authorities = new ArrayList<>();
        for(GrantedAuthority authority : userPrincipal.getAuthorities()){
            authorities.add(authority.getAuthority());
        }
        return authorities.toArray(new String[0]);
    }
}
