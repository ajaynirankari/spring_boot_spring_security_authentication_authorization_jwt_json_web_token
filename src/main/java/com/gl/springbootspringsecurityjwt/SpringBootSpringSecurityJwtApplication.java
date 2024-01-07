package com.gl.springbootspringsecurityjwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;

@SpringBootApplication
public class SpringBootSpringSecurityJwtApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringBootSpringSecurityJwtApplication.class, args);
    }
}

@RestController
class MyController {

    @Autowired
    private MyUserRepo repo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/")
    public String defaultMethod() {
        return "This is default API for everyone";
    }

    @GetMapping("/home")
    public String homeMethod() {
        return "This is home API for everyone";
    }

    @PostMapping("/register")
    public String register(@RequestBody MyUser myUser) {
        if (myUser.getUsername() == null || myUser.getPassword() == null) {
            return "user name or password can not be null";
        }
        if (myUser.getUsername().trim().isEmpty() || myUser.getPassword().trim().isEmpty()) {
            return "user name or password can not be empty";
        }
        myUser.setPassword(passwordEncoder.encode(myUser.getPassword()));
        if (myUser.getRoles() == null) {
            myUser.setRoles(Set.of("USER"));
        }
        repo.save(myUser);
        return "user registration done";
    }

    @PostMapping("/token")
    public ResponseToken getToken(@RequestBody MyUser myUser) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(myUser.getUsername(), myUser.getPassword()));
            return ResponseToken.ok(JwtUtil.generateToken(myUser), JwtUtil.generateRefreshToken(myUser));
        } catch (Exception e) {
            return ResponseToken.error(e.getMessage());
        }
    }

    @GetMapping("/tokenFromRefreshToken")
    public ResponseToken getTokenFromRefreshToken(@RequestParam String refreshToken) {
        try {
            String username = JwtUtil.getUsernameFromRefreshToken(refreshToken);
            MyUser myUser = repo.findByUsername(username);
            return ResponseToken.ok(JwtUtil.generateToken(myUser), refreshToken);
        } catch (Exception e) {
            return ResponseToken.error(e.getMessage());
        }
    }

    @GetMapping("/public/api1")
    public String apiMethod1() {
        return "This is for authenticated public API 1";
    }

    @GetMapping("/public/api2")
    public String apiMethod2() {
        return "This is for authenticated public API 2";
    }

    @GetMapping("/admin/api1")
    public String adminApiMethod1() {
        return "Thigs is for authenticated admin API 1";
    }

    @GetMapping("/admin/api2")
    public String adminApiMethod2() {
        return "This is for authenticated admin API 2";
    }

    @PreAuthorize("hasRole('ADMINSP')")
    @GetMapping("/private/api1")
    public String privateAdminApiMethod1() {
        return "This is for authenticated private admin API 1";
    }

    @PreAuthorize("hasRole('ADMINSP')")
    @GetMapping("/private/api2")
    public String privateAdminApiMethod2() {
        return "This is for authenticated private admin API 2";
    }

}

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfiguration {

    @Autowired
    private JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/", "/home", "/token", "/register", "/tokenFromRefreshToken").permitAll()
                        .requestMatchers("/public/**").hasRole("USER")
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        var authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner loadInitialUsersInDB(MyUserRepo repo) {
        return args -> {
            MyUser user1 = new MyUser();
            user1.setUsername("admin");
            user1.setPassword(passwordEncoder().encode("admin"));
            user1.setRoles(Set.of("ADMIN", "USER"));
            repo.deleteByUsername(user1.getUsername());
            repo.save(user1);
        };
    }
}

@Component
class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private MyUserRepo repo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        MyUser dbUser = repo.findByUsername(username);
        if (dbUser == null) {
            throw new UsernameNotFoundException("username: " + username + " not found");
        }
        return User.builder()
                .username(dbUser.getUsername())
                .password(dbUser.getPassword())
                .roles(dbUser.getRoles().toArray(String[]::new))
                .build();
    }
}

@Component
class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String authorizationHeader = request.getHeader("Authorization");
            if (authorizationHeader == null) {
                filterChain.doFilter(request, response);
                return;
            }

            String tokenPrefix = "Bearer ";
            String token = authorizationHeader.substring(tokenPrefix.length());
            String username = JwtUtil.getUsername(token);
            if (username != null && !JwtUtil.isTokenExpiration(token)) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()));
            }
        } catch (Exception e) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write(e.getMessage());
            response.getWriter().flush();
            return;
        }

        filterChain.doFilter(request, response);
    }
}

class JwtUtil {

    public static String generateToken(MyUser myUser) {
        return Jwts.builder()
                .claim("username", myUser.getUsername())
                .claim("roles", myUser.getRoles())
                .issuedAt(new Date(Instant.now().toEpochMilli()))
                .expiration(new Date(Instant.now().plus(1, ChronoUnit.DAYS).toEpochMilli()))
                .signWith(signingKey())
                .compact();
    }

    public static String generateRefreshToken(MyUser myUser) {
        return Jwts.builder()
                .claim("username", myUser.getUsername())
                .claim("roles", myUser.getRoles())
                .issuedAt(new Date(Instant.now().toEpochMilli()))
                .expiration(new Date(Instant.now().plus(30, ChronoUnit.DAYS).toEpochMilli()))
                .signWith(refreshSigningKey())
                .compact();
    }

    public static String getUsername(String token) {
        return (String) getClaims(token).get("username");
    }

    public static boolean isTokenExpiration(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    public static boolean isRefreshTokenExpiration(String token) {
        return getRefreshClaims(token).getExpiration().before(new Date());
    }

    public static String getUsernameFromRefreshToken(String token) {
        return (String) getRefreshClaims(token).get("username");
    }

    private static Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private static Claims getRefreshClaims(String token) {
        return Jwts.parser()
                .verifyWith(refreshSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private static SecretKey signingKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    private static SecretKey refreshSigningKey() {
        return Keys.hmacShaKeyFor(REFRESH_SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    private static final String SECRET_KEY = "ab56gdf456s6er3as1232425bxv57fg4dg6dg3c";
    private static final String REFRESH_SECRET_KEY = "throng35345dff8gjjjas1232425bxv57fg4dg6dg3c";
}

interface MyUserRepo extends JpaRepository<MyUser, Long> {

    MyUser findByUsername(String username);

    @Transactional
    void deleteByUsername(String username);
}

@Data
@Entity
class MyUser {

    @Id
    @GeneratedValue
    private long id;

    @Column(unique = true)
    private String username;
    private String password;

    private Set<String> roles;
}

@Data
class ResponseToken {
    private String token;
    private String refreshToken;
    private String error;

    private ResponseToken(String error) {
        this.error = error;
    }

    private ResponseToken(String token, String refreshToken) {
        this.token = token;
        this.refreshToken = refreshToken;
    }

    public static ResponseToken error(String error) {
        return new ResponseToken(error);
    }

    public static ResponseToken ok(String token, String refreshToken) {
        return new ResponseToken(token, refreshToken);
    }
}
