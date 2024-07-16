package com.example.finals.controller;

import com.example.finals.model.User;
import com.example.finals.security.CustomUserDetailsService;
import com.example.finals.security.JwtUtil;
import com.example.finals.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/api")
public class AuthenticationController {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private UserService userService;

    @Autowired
    @Qualifier("passwordEncoder")
    private PasswordEncoder passwordEncoder;

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody User user) throws Exception {
        logger.debug("Attempting to authenticate user: {}", user.getUsername());
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        } catch (BadCredentialsException e) {
            logger.error("Invalid credentials for user: {}", user.getUsername());
            return ResponseEntity.status(401).body("Incorrect username or password");
        } catch (Exception e) {
            logger.error("Authentication failed for user: {}", user.getUsername(), e);
            throw new Exception("Authentication failed", e);
        }

        final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        final String jwt = jwtUtil.generateToken(userDetails);

        logger.debug("User authenticated successfully: {}", user.getUsername());
        return ResponseEntity.ok(jwt);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user) {
        logger.debug("Registering new user: {}", user.getUsername());
        logger.debug("Original password: {}", user.getPassword());
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        logger.debug("Encoded password: {}", encodedPassword);
        user.setPassword(encodedPassword);
        User newUser = userService.saveUser(user);
        logger.debug("User registered successfully: {}", user.getUsername());
        return ResponseEntity.ok(newUser);
    }

}
