# Steps to configure resource server with  OAuth2
### Dependency
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
		</dependency>
### JWT role converter
- We have to define and configure a jwt role converter to convert plain text role from token to GrantetAuthority,
because spring security consider only object of GrantedAuthority
- Check class **KeycloakRoleConverter.java**

### Security filter chain configuration
- Have to configure **http.oauth2ResourceServer()**
- Check class **OAuth2SecurityConfig.Java**

### Cert configuration
- resource server needs keys to validate jwt token, to get the certs with keys, we have to configure auth-server url for cert
- spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:8081/realms/pkBank/protocol/openid-connect/certs
- we can get this url from auth server http://localhost:8081/realms/pkBank/.well-known/openid-configuration
- Above url is standard for all auth server like google, facebook etc.
- realms -> realms Setting -> endpoints

# Steps to configure oauth with social login like FB, Github, Google
- This will give user a option on login page to login using all the registered client
- Like Facebook, GitHub, Google, Keycloak, Okta
### Dependency
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-oauth2-client</artifactId>
		</dependency>

### Security filter chain configuration
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(request -> request.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .oauth2Login(Customizer.withDefaults());

        return http.build();
    }

- we have to enable .oauth2Login(), to see option to login with registered client

### Client registration
    @Bean
    public ClientRegistrationRepository clientRegistration() {
        return new InMemoryClientRegistrationRepository(googleClientRegistration());
    }

    private ClientRegistration googleClientRegistration(){
        return CommonOAuth2Provider.GOOGLE
                .getBuilder("google")
                .clientId("")
                .clientSecret("")
                .build();
    }

- It simply mean configure auth server from where we want to generate token
- For well known auth server like FB, Google, GitHub, Okta, we have **CommonOAuth2Provider** which have all the details configure just we need to update clientId and secrete
- Developer generally uses **InMemoryClientRegistrationRepository** to register client, its an implementation of **ClientRegistrationRepository**

## Client registration for keycloak
    @Bean
    public ClientRegistration keyckloakClientRegistration() {
        String clientId = environment.getProperty("application.security.keycloak.client-id");
        String clientSecret = environment.getProperty("application.security.keycloak.client-secret");
        String tokenUri = environment.getProperty("application.security.keycloak.token-uri");
        String authUri = environment.getProperty("application.security.keycloak.auth-uri");
        String issuerUri = environment.getProperty("application.security.keycloak.issuer-uri");
        String userInfoUri = environment.getProperty("application.security.keycloak.userInfo-uri");
        String jwkSetUri = environment.getProperty("application.security.keycloak.jwks-uri");
        String redirectUri = "{baseUrl}/login/oauth2/code/{registrationId}";

        return ClientRegistration.withRegistrationId(KEYCLOAK)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                .scope(new String[]{"openid", "email"})
                .issuerUri(issuerUri)
                .userInfoUri(userInfoUri)
                .jwkSetUri(jwkSetUri)
                .userNameAttributeName("preferred_username")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .tokenUri(tokenUri)
                .authorizationUri(authUri)
                .build();
    }

## Client registration with properties
	spring.security.oauth2.client.registration.github.client-id=""
	spring.security.oauth2.client.registration.github.client-secret=""

	it will register a client with id github in registry.
    Note: Both the configuration will not work simultanously as we are defining
    our own clientRegistrationRepository

### Configuration server as client to get token internally using client_credential grant type flow
- Along with the Client registration configuration, we have to configure ClientManager with a ClientProvider.
  - While setting up the provider we have to define which grant type flow it will for.

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
    - Sample code to get token

            @Service
            public class TokenService {
                @Autowired
                private OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
        
                public String getAccessToken(){
                    OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                            .withClientRegistrationId("keycloak_internal")
                            .principal("system-app")
                            .build();

                OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);
                if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
                    throw new IllegalStateException("User is not authorized or access token is missing");
                }
    
                return authorizedClient.getAccessToken().getTokenValue();
            }
- If we want to use keycloak for both login using authorization-code grant type flow and get token using client-credential-flow, we have register another keycloak client with desired flow
- Like here i have registered 2 keycloak client with registration-id "keycloak" & "keycloak_internal"
 

# oauthpoc-client — Documentation (top to bottom)

## Overview
- Spring Boot OAuth2 client demo.
- Shows: OAuth2 login (authorization_code), programmatic token acquisition (client_credentials), and a token REST endpoint.

## `config/Oauth2Config.java`
- Registers clients (properties or in-memory).
  - Builds `OAuth2AuthorizedClientManager` for programmatic token flow.

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

## `controller/TokenController.java`
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

    /*Dynamically fetch the token from auth server for client-credential flow, no user involved.*/
    @GetMapping("/google-token")
    public ResponseEntity<?> getGoogleToken(OAuth2AuthenticationToken authentication){

        return ResponseEntity.status(HttpStatus.OK).body(tokenService.getAccessToken());
    }


    private OAuth2AuthenticationToken getAuthentication(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication instanceof OAuth2AuthenticationToken){
            return (OAuth2AuthenticationToken) authentication;
        }
        return null;
    }

## `service/TokenService.java`
- Programmatically request access token for a registered client id (e.g., `keycloak_internal`).

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
                .withClientRegistrationId("keycloak_internal")
                .principal("system-app")
                .build();

        OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);
        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            throw new IllegalStateException("User is not authorized or access token is missing");
        }

        return authorizedClient.getAccessToken().getTokenValue();
    }

    }

# End of `README.md`

