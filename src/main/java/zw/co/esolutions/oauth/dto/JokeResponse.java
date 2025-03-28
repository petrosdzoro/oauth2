package zw.co.esolutions.oauth.dto;

import lombok.Data;

@Data // Lombok annotation for getters/setters
public class JokeResponse {
    private String type;
    private String setup;
    private String punchline;
}