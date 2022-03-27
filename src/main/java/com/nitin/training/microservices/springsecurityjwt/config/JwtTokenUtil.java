package com.nitin.training.microservices.springsecurityjwt.config;

import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.nitin.training.microservices.springsecurityjwt.exception.JwtTokenMalformedException;
import com.nitin.training.microservices.springsecurityjwt.exception.JwtTokenMissingException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class JwtTokenUtil {
	
	@Value("${jwt.secret}")
	private String jwtSecret;
	
	@Value("${jwt.token.validity}")
	private long tokenValidity;
	
	public Claims getClaims(final String token) {
		try {
			Claims body = Jwts.parser().setSigningKey(jwtSecret.getBytes()).parseClaimsJws(token).getBody();
			return body;
		} catch (Exception e) {
			System.out.println(e.getMessage() + " => " + e);
		}
		return null;
	}
	
	public String generateToken(String id) {
		
		String jwtToken = Jwts.builder()
		        .claim("name", "Jane Doe")
		        .claim("email", "jane@example.com")
		        .setSubject(id)
		        .setId(id)
		        .setIssuedAt(Date.from(Instant.now()))
		        .setExpiration(Date.from(Instant.now().plus(tokenValidity, ChronoUnit.MILLIS)))
		        .signWith(SignatureAlgorithm.HS256,jwtSecret.getBytes())
		        .compact();
		
		return jwtToken;
	}
	public String getUsernameFromToken(final String token){
		Claims body  = getClaims(token);
		return body.getSubject();
	
	}
	
	public boolean validateToken(final String token, UserDetails details) throws JwtTokenMalformedException, JwtTokenMissingException {
		boolean tokenValid= false;
		try {
			Jwts.parser().setSigningKey(jwtSecret.getBytes()).parseClaimsJws(token);
			tokenValid = true;
		} catch (SignatureException ex) {
			throw new JwtTokenMalformedException("Invalid JWT signature");
		} catch (MalformedJwtException ex) {
			throw new JwtTokenMalformedException("Invalid JWT token");
		} catch (ExpiredJwtException ex) {
			throw new JwtTokenMalformedException("Expired JWT token");
		} catch (UnsupportedJwtException ex) {
			throw new JwtTokenMalformedException("Unsupported JWT token");
		} catch (IllegalArgumentException ex) {
			throw new JwtTokenMissingException("JWT claims string is empty.");
		}
		return tokenValid;
	}

}
