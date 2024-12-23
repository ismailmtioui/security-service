package dcc.tp2.security_microservice.controller;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class Oauth2Controller {

    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final UserDetailsService userDetailsService;

    public Oauth2Controller(AuthenticationManager authenticationManager, JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestParam String username, @RequestParam String password, @RequestParam String userType) {
        String combinedUsername = username + ":" + userType;

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(combinedUsername, password)
        );

        Instant now = Instant.now();
        String scope = authentication.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .collect(Collectors.joining(" "));

        String accessToken = generateToken(authentication.getName(), scope, now, 2);
        String refreshToken = generateToken(authentication.getName(), null, now, 15);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("Access_Token", accessToken);
        tokens.put("Refresh_Token", refreshToken);

        return tokens;
    }

    @PostMapping("/refresh-token")
    public Map<String, String> refreshToken(@RequestParam String refreshToken, @RequestParam String userType) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new IllegalArgumentException("Refresh token is required.");
        }

        Jwt decodedToken = jwtDecoder.decode(refreshToken);
        String username = decodedToken.getSubject();
        String combinedUsername = username + ":" + userType;

        UserDetails userDetails = userDetailsService.loadUserByUsername(combinedUsername);

        Instant now = Instant.now();
        String scope = userDetails.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .collect(Collectors.joining(" "));

        String newAccessToken = generateToken(userDetails.getUsername(), scope, now, 2);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("Access_Token", newAccessToken);
        tokens.put("Refresh_Token", refreshToken);

        return tokens;
    }

    private String generateToken(String subject, String scope, Instant issuedAt, int durationMinutes) {
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer("MS_sec")
                .subject(subject)
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plus(durationMinutes, ChronoUnit.MINUTES));

        if (scope != null) {
            claimsBuilder.claim("scope", scope);
        }

        JwtClaimsSet claimsSet = claimsBuilder.build();
        return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }
}
