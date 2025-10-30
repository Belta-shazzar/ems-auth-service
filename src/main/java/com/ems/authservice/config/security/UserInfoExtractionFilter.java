package com.ems.authservice.config.security;

import com.ems.authservice.config.security.enums.UserHttpHeaders;
import com.ems.authservice.config.security.user.AppUserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class UserInfoExtractionFilter extends OncePerRequestFilter {
  private final AppUserService userService;

  @Override
  protected void doFilterInternal(
          HttpServletRequest request,
          HttpServletResponse response,
          FilterChain filterChain
  ) throws ServletException, IOException {
    final String email = request.getHeader(UserHttpHeaders.X_EMAIL);

    if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = userService.loadUserByUsername(email);
      UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
              userDetails, null, userDetails.getAuthorities()
      );
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    filterChain.doFilter(request, response);
  }
}
