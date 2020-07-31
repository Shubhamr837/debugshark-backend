package com.debugshark.security;

public interface ISecurityUserService {

    String validatePasswordResetToken(long id, String token);

}
