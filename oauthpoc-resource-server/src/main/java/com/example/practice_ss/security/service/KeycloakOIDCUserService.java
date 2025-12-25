package com.example.practice_ss.security.service;

import com.example.practice_ss.constans.ApplicationConstants;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.*;
/*oAuth login will store the Oidc (open id connect) user mapped with jsession id for further authorization,
* default oidc user doesnt holds the roles coming from auth server,
* so, this the custom implementation to issue new oidc user with roles*/

/*If user not present in DB it will create with same email and default password*/
@Profile(ApplicationConstants.OAUTH2)
@Service
public class KeycloakOIDCUserService extends OidcUserService {

    @Autowired(required = false)
    private CustomJdbcUserDetailsService userDetailsService;

    private final String DEFAULT_PASSWORD = "khuljasimsim";

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        // Get the user details from IDP by hiting user-info endpoint
        OidcUser oidcUser = super.loadUser(userRequest);

        Set<GrantedAuthority> authorities = new HashSet<>(oidcUser.getAuthorities());
        authorities.addAll(getRolesFromIdp(userRequest));
        createUserIfNotExists(oidcUser, userRequest);

        return new DefaultOidcUser(
                authorities,
                oidcUser.getIdToken(),
                oidcUser.getUserInfo()
        );
    }

    private Collection<String> getRolesFromToken(OidcUserRequest userRequest){
        List<String> roles = new ArrayList<>();
        try {
            // Decode access token
            String accessTokenValue = userRequest.getAccessToken().getTokenValue();
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(accessTokenValue);
            Map<String, Object> claims = signedJWT.getJWTClaimsSet().getClaims();

            // Extract Keycloak roles
            Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
            if (realmAccess != null) {
                roles.addAll((List<String>) realmAccess.get("roles"));
            }
        } catch (Exception e) {
            throw new OAuth2AuthenticationException("Failed to parse Keycloak access token");
        }
        return roles;
    }

    /*Extract roles from the token*/
    private Collection<GrantedAuthority> getRolesFromIdp(OidcUserRequest oidcUserRequest){
        Set<GrantedAuthority> authorities = new HashSet<>();

        Collection<String> roles = getRolesFromToken(oidcUserRequest);
        if (!roles.isEmpty()) {
            roles.forEach(role ->
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + role))
            );
        }
        return authorities;
    }

    /*Create the user if login for the first time*/
    private void createUserIfNotExists(OidcUser oidcUser, OidcUserRequest oidcUserRequest){
        String username = oidcUser.getClaimAsString("email");
        if(!userDetailsService.userExists(username)){
            Collection<String> roles = getRolesFromToken(oidcUserRequest);
            UserDetails user = User.withUsername(username)
                    .password(DEFAULT_PASSWORD)
                    .authorities(roles.stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                            .toList()
                    )
                    .build();
            userDetailsService.createUser(user);
        }

    }
}
