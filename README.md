# Steps to configure resource server with  OAuth2
### Dependency
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
		</dependency>
### JWT role converter
- We have to define and configure a jwt role converter to convert plain text role from token to GrantetAuthority,
because spring security consider only object of GrantedAuthority
```java
  /* purpose of this to extract the roles from token, so that resource it can be use for api access.
  * This is only required in resource server config.*/
    public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
        @Override
        public Collection<GrantedAuthority> convert(Jwt source) {
            Map<String, Object> realmAccess = (Map<String, Object>) source.getClaims().get("realm_access");
            if (realmAccess == null || realmAccess.isEmpty()) {
                return new ArrayList<>();
            }
            Collection<GrantedAuthority> returnValue = ((List<String>) realmAccess.get("roles"))
              .stream().map(roleName -> "ROLE_" + roleName)
              .map(SimpleGrantedAuthority::new)
              .collect(Collectors.toList());
            return returnValue;
        }
    }
```
### Resource Server Configuration
- Have to configure **http.oauth2ResourceServer()**
```java
/*Responsible to make application as resource server, it requires a JWT role converter, so that it can validate the roles*/
public void configureResourceServer(HttpSecurity http) throws Exception {
  JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
  jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

  http.oauth2ResourceServer(orc -> orc.jwt(jwtConfigurer ->
          jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));
}
```

### Cert configuration
- resource server needs keys to validate jwt token, to get the certs with keys, we have to configure auth-server url for cert
- spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:8081/realms/pkBank/protocol/openid-connect/certs
- we can get this url from auth server http://localhost:8081/realms/pkBank/.well-known/openid-configuration
- Above url is standard for all auth server like google, facebook etc.
- realms -> realms Setting -> endpoints

# Steps to configure oauth with social login like FB, Github, Google (oAuth Login )
- This will give user a option on login page to login using all the registered client
- Like Facebook, GitHub, Google, Keycloak, Okta
### Dependency
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-oauth2-client</artifactId>
		</dependency>

### OAuth2 configuration for login using UI
- we have to enable .oauth2Login(), to see option to login with registered client
```java
    /*Responsible for oauth login flow*/
    public void configureOauth2Login(HttpSecurity http) throws Exception {
        http.oauth2Login(oc -> oc.defaultSuccessUrl("/myCards",true)
                .userInfoEndpoint(userInfo ->
                        userInfo.oidcUserService(new KeycloakOIDCUserService())
                )
        );
    }
```
```java
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
```
### Client registration (Using code)
- It simply means configure auth server from where we want to generate token.
- For well known auth server like FB, Google, GitHub, Okta, we have **CommonOAuth2Provider** which have all the details configure just we need to update clientId and secrete
- Developer generally uses **InMemoryClientRegistrationRepository** to register client, its an implementation of **ClientRegistrationRepository**

```java
    @Bean
    public ClientRegistrationRepository clientRegistration() {
        return new InMemoryClientRegistrationRepository(googleClientRegistration(),keyckloakClientRegistration());
    }
    
    //Google client registration
    private ClientRegistration googleClientRegistration(){
        return CommonOAuth2Provider.GOOGLE
                .getBuilder("google")
                .clientId("")
                .clientSecret("")
                .build();
    }
    
    //Keycloak client registration
    private ClientRegistration keyckloakClientRegistration() {
      return ClientRegistration.withRegistrationId(KEYCLOAK)
              .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
              .scope(new String[]{"openid", "email"})
              .issuerUri("")
              .userInfoUri("")
              .jwkSetUri("")
              .userNameAttributeName("preferred_username")
              .clientId("")
              .clientSecret("")
              .tokenUri("")
              .authorizationUri("")
              .build();
    }
```
## Client registration (using properties)
```properties
spring.security.oauth2.client.registration.github.client-id=""
spring.security.oauth2.client.registration.github.client-secret=""

spring.security.oauth2.client.provider.pkidp.authorization-uri=""
spring.security.oauth2.client.provider.pkidp.token-uri=""
```
- it will register a client with id **Github** in registry.
- We have to provide provider details for non well known auth server like keycloak, okta etc.
- **Note:** Both the configuration will not work simultaneously as we are defining our own clientRegistrationRepository.
```java
//This Spring class is responsible to read these properties.
@ConfigurationProperties(prefix = "spring.security.oauth2.client")
public class OAuth2ClientProperties implements InitializingBean {...}
```
### Configure server as client to get token internally using client_credential/Authorization-code grant type flow
- Along with the Client registration configuration, we have to configure ClientManager with a ClientProvider.
- While setting up the provider we have to define which grant type flow it will for.
```java
        @Bean
        public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {
    
            OAuth2AuthorizedClientProvider authorizedClientProvider =
                    OAuth2AuthorizedClientProviderBuilder.builder()
                            .clientCredentials()
                            .refreshToken()  // optional, if you want refresh tokens
                            .build();
    
            DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                    new DefaultOAuth2AuthorizedClientManager(
                            clientRegistrationRepository,
                            authorizedClientRepository);
    
            authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
            return authorizedClientManager;
        }
```
- Sample code to get token
```java
* authorize()
        └── find existing token?
        ├── yes → return it
          └── no
            └── client_credentials flow
              └── POST /token
                └── client_id + client_secret
                  └── access_token
* Majorly this use to fetch resources from the different auth server, it not mandatory client-credential, it can be authorization-code flow*/

        @Service
        public class TokenService {
            @Autowired
            private OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
        
            public String getAccessToken(){
                OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                        .withClientRegistrationId("keycloak")
                        .principal("system-app")
                        .build();

            OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest); //invoke authorization, if authorization-code flow, popup will be generated for use to enter credential
            if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
                throw new IllegalStateException("User is not authorized or access token is missing");
            }
    
            return authorizedClient.getAccessToken().getTokenValue();
        }
```
- If we want to use keycloak for both login using authorization-code grant type flow and get token using client-credential-flow, we have register another keycloak client with desired flow

## Getting currently logged in user token
```java
    /*Returns the access token of the currently logged-in user
    * Browser → Keycloak/Google Login
        → Redirect back with code
        → Spring exchanges code for tokens
        → Tokens stored in session (AuthorizedClientService)*/

    @GetMapping("/token")
    public ResponseEntity<?> getToken(){

        OAuth2AuthenticationToken authenticationToken = getAuthentication();
        String token = "";
        if(authenticationToken != null){
            OAuth2AuthorizedClient authorizedClient = auth2AuthorizedClientService
                    .loadAuthorizedClient(authenticationToken.getAuthorizedClientRegistrationId(), authenticationToken.getName());
            token = authorizedClient.getAccessToken().getTokenValue();
        }

        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    private OAuth2AuthenticationToken getAuthentication(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication instanceof OAuth2AuthenticationToken){
            return (OAuth2AuthenticationToken) authentication;
        }
        return null;
    }
```
# Filters invoked to identify login and prepare authentication object
| Filter                                 | How it decides                 |
| -------------------------------------- | ------------------------------ |
| `UsernamePasswordAuthenticationFilter` | URL + HTTP method              |
| `BasicAuthenticationFilter`            | `Authorization: Basic` header  |
| `BearerTokenAuthenticationFilter`      | `Authorization: Bearer` header |
| `OAuth2LoginAuthenticationFilter`      | `/login/oauth2/code/*`         |
| `RememberMeAuthenticationFilter`       | Remember-me cookie             |
| `AnonymousAuthenticationFilter`        | No authentication found        |

```java
Request
↓
Check Bearer Header → BearerTokenAuthenticationFilter
↓
Check Basic Header → BasicAuthenticationFilter
↓
Check /login POST → UsernamePasswordAuthenticationFilter
↓
Check OAuth callback → OAuth2LoginAuthenticationFilter
↓
Session Restore
↓
AnonymousAuthenticationFilter
```
# End of `README.md`

