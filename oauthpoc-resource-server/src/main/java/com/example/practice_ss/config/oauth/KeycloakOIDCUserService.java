package com.example.practice_ss.config.oauth;

import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.*;
/*oAuth login will store the Oidc (open id connect) user mapped with jsession id for further authorization,
* default oidc user doesnt holds the roles coming from auth server,
* so, this the custom implementation to issue new oidc user with roles*/

public class KeycloakOIDCUserService extends OidcUserService {

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);

        Set<GrantedAuthority> authorities = new HashSet<>(oidcUser.getAuthorities());

        try {
            // Decode access token
            String accessTokenValue = userRequest.getAccessToken().getTokenValue();
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(accessTokenValue);
            Map<String, Object> claims = signedJWT.getJWTClaimsSet().getClaims();

            // Extract Keycloak roles
            Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
            if (realmAccess != null) {
                List<String> roles = (List<String>) realmAccess.get("roles");
                if (roles != null) {
                    roles.forEach(role ->
                            authorities.add(new SimpleGrantedAuthority("ROLE_" + role))
                    );
                }
            }

        } catch (Exception e) {
            throw new OAuth2AuthenticationException("Failed to parse Keycloak access token");
        }

        return new DefaultOidcUser(
                authorities,
                oidcUser.getIdToken(),
                oidcUser.getUserInfo()
        );
    }
}
