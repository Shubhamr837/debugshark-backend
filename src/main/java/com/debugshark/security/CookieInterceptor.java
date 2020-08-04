package com.debugshark.security;

import com.debugshark.persistence.model.User;
import com.debugshark.util.Constants;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Collection;

@Component
public class CookieInterceptor implements HandlerInterceptor {
    @Autowired
    private AuthenticationManager authenticationManager;

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

        @Override
        public boolean preHandle(
                HttpServletRequest httpRequest, HttpServletResponse httpResponse, Object handler) throws Exception {

                /*String cookie_value = readCookie(Constants.authenticationCookieKey, httpRequest);
                if (cookie_value != null) {
                    byte[] decodedBytes = Base64.getDecoder().decode(cookie_value);
                    JSONObject jsonObject = new JSONObject(new String(decodedBytes));
                    Authentication authentication = authWithAuthManager(httpRequest,jsonObject.getString("username"),jsonObject.getString("password"));
                    handle(httpRequest,httpResponse,authentication);
                }

            System.out.println("Request url"+httpRequest.getRequestURL());*/
            return false;
        }
        @Override
        public void postHandle(
                HttpServletRequest httpRequest, HttpServletResponse httpResponse, Object handler,
                ModelAndView modelAndView) throws Exception {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
           /* if ((authentication!=null)&&!(authentication instanceof AnonymousAuthenticationToken)) {
                String cookie_value = readCookie(Constants.authenticationCookieKey, httpRequest);
                if (cookie_value == null) {
                    createAndAddCookie(authentication, httpResponse);
                }
                else {

                }
            }*/

        }

        @Override
        public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                    Object handler, Exception exception) throws Exception {

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
            System.out.println("Response has already been committed. Unable to redirect to " + targetUrl);
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
