package com.debugshark.spring;

import com.debugshark.persistence.model.User;
import com.debugshark.util.Constants;
import org.json.JSONObject;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Collection;


public class CookieFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager ;
    private final RedirectStrategy redirectStrategy;

    public static final String secretKey = "";

    CookieFilter(AuthenticationManager authenticationManager, RedirectStrategy redirectStrategy){
        this.authenticationManager = authenticationManager;
        this.redirectStrategy = redirectStrategy;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse,
            FilterChain chain) throws IOException, ServletException
    {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if ((authentication!=null)&&!(authentication instanceof AnonymousAuthenticationToken)) {
            String cookie_value = readCookie(Constants.authenticationCookieKey, httpRequest);
            if (cookie_value == null) {
                createAndAddCookie(authentication, httpResponse);
            }
            else {
                if(!httpRequest.getRequestURL().toString().endsWith("homepage.html")) {
                    handle(httpRequest,httpResponse,authentication);
                }
            }
            }
        else {
            String cookie_value = readCookie(Constants.authenticationCookieKey, httpRequest);
            if (cookie_value != null) {
                byte[] decodedBytes = Base64.getDecoder().decode(cookie_value);
                JSONObject jsonObject = new JSONObject(new String(decodedBytes));
                Authentication authentication1 = authWithAuthManager(httpRequest,jsonObject.getString("username"),jsonObject.getString("password"));
                System.out.println("Logged in via cookie");
                handle(httpRequest,httpResponse,authentication1);
            }
        }
        System.out.println("Request url"+httpRequest.getRequestURL());
        chain.doFilter(httpRequest,httpResponse);

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return !(path.endsWith("login")||path.endsWith("homepage.html")||path.endsWith("registration.html"));
    }

    public Authentication authWithAuthManager( HttpServletRequest request ,String username,String password  )
    {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username,password);
        authToken.setDetails(new WebAuthenticationDetails(request));

        Authentication authentication = authenticationManager.authenticate(authToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        return authentication;
    }
    public String readCookie(String key,HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        String cookie_value = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(key)) {
                    cookie_value = cookie.getValue() ;
                }
            }
        }
        if(cookie_value!=null) {
            return cookie_value;
        } else {
            System.out.println("authentication cookie absent");
            return null;
        }
    }
    private boolean createAndAddCookie(Authentication authentication,HttpServletResponse response){
        String username = ((User)(authentication.getPrincipal())).getEmail();

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("username",username);
        jsonObject.put("password",authentication.getCredentials().toString());

        return addCookie(jsonObject.toString(),response);
    }
    private boolean addCookie(String cookie_value,HttpServletResponse response){
        Cookie cookie = new Cookie(Constants.authenticationCookieKey, Base64.getEncoder().withoutPadding().encodeToString(cookie_value.getBytes()));
        cookie.setMaxAge(60*60*24*180);
        cookie.setPath("/");
        response.addCookie(cookie);
        return true;
    }

    protected void handle(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws IOException {
        final String targetUrl = determineTargetUrl(authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }
        System.out.println("Sending Redirect");
        redirectStrategy.sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(final Authentication authentication) {
        boolean isUser = false;
        boolean isAdmin = false;
        final Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        for (final GrantedAuthority grantedAuthority : authorities) {
            if (grantedAuthority.getAuthority().equals("READ_PRIVILEGE")) {
                isUser = true;
            } else if (grantedAuthority.getAuthority().equals("WRITE_PRIVILEGE")) {
                isAdmin = true;
                isUser = false;
                break;
            }
        }
        if (isUser) {
            String username;
            if (authentication.getPrincipal() instanceof User) {
                username = ((User)authentication.getPrincipal()).getEmail();
            }
            else {
                username = authentication.getName();
            }

            return "/homepage.html?user="+username;
        } else if (isAdmin) {
            return "/console.html";
        } else {
            throw new IllegalStateException();
        }
    }

    protected RedirectStrategy getRedirectStrategy() {
        return redirectStrategy;
    }

}