package zw.co.esolutions.oauth.controller;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import zw.co.esolutions.oauth.dto.JokeResponse;

import java.security.Principal;

@Slf4j
@RestController
public class MainController {
    Gson gson = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.IDENTITY).setPrettyPrinting().create();

    @RequestMapping("/")
    public String home(){
        RestTemplate restTemplate = new RestTemplate();
        JokeResponse response = restTemplate.getForObject("https://official-joke-api.appspot.com/random_joke", JokeResponse.class);
        return gson.toJson(response);
    }

    @RequestMapping("/user")
    public Principal user(Principal user, @AuthenticationPrincipal OidcUser oidcUser){
        String jwtToken = oidcUser.getIdToken().getTokenValue();
        log.info("JWT TOKEN : "+jwtToken);
        return user;
    }

    @RequestMapping("/my-info")
    public String myInfo(
            @RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient client) {

        // Validate token
        OAuth2AccessToken accessToken = client.getAccessToken();
        log.info("Access Token: {}", accessToken.getTokenValue());
        log.info("Expires At: {}", accessToken.getExpiresAt());

        // API URL (fetching user's own profile)
        String resourceUrl = "https://people.googleapis.com/v1/people/me?personFields=names,emailAddresses,photos";

        // Prepare request with ACCESS TOKEN (not ID token)
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken.getTokenValue()); // Correct: Uses access token

        // Make request
        ResponseEntity<String> response = new RestTemplate().exchange(
                resourceUrl,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class
        );

        String responseBody = response.getBody();
        log.info("Response : {}",responseBody);
        return responseBody;
    }

    @RequestMapping("/contacts")
    public String getContacts(
            @RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient client) {

        // Validate token
        OAuth2AccessToken accessToken = client.getAccessToken();
        log.info("Access Token: {}", accessToken.getTokenValue());
        log.info("Expires At: {}", accessToken.getExpiresAt());

        // API URL (fetching user's contacts)
        String resourceUrl = "https://people.googleapis.com/v1/people/me/connections?personFields=names,emailAddresses,phoneNumbers";

        // Prepare request with ACCESS TOKEN (not ID token)
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken.getTokenValue()); // Correct: Uses access token

        // Make request
        ResponseEntity<String> response = new RestTemplate().exchange(
                resourceUrl,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class
        );

        String responseBody = response.getBody();
        log.info("Response : {}",responseBody);
        return responseBody;
    }
}
