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
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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

    @PostMapping("/token")
    public String getToken(@RequestBody MyUser myUser) {
        System.out.println("getToken myUser = " + myUser);
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(myUser.getUsername(), myUser.getPassword()));
        } catch (Exception e) {
            return e.getMessage();
        }
        return JwtUtil.generateToken(myUser);
    }

    @PostMapping("/register")
    public String register(@RequestBody MyUser myUser) {
        System.out.println("register myUser = " + myUser);
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

    @GetMapping("/home")
    public String homeMethod() {
        return "This is home API for everyone";
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
        return "This is for authenticated admin API 1";
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
                        .requestMatchers("/", "/home", "/token", "/register").permitAll()
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

class JwtUtil {
    private static final String SECRET_KEY = "ab56gdf456s6er3as1232425bxv57fg4dg6dg3c";
    private static final int MINUTES_5 = 5;

    public static String generateToken(MyUser myUser) {
        return Jwts.builder()
                .claim("username", myUser.getUsername())
                .claim("roles", myUser.getRoles())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + (MINUTES_5 * 60 * 1000)))
                .signWith(getSigningKey())
                .compact();
    }

    public static String getUsername(String token) {
        return (String) getClaims(token).get("username");
    }

    public static boolean isTokenExpiration(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    public static Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private static SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
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
            System.out.println("--- doFilter() :: authorizationHeader = " + authorizationHeader);
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