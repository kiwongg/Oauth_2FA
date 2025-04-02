package com.example.oauth.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class CatFactService {

    private static final String CAT_API_URL = "https://catfact.ninja/fact";

    public String getRandomCatFact() {
        RestTemplate restTemplate = new RestTemplate();
        CatFactResponse response = restTemplate.getForObject(CAT_API_URL, CatFactResponse.class);

        if (response != null && response.getFact() != null) {
            return response.getFact();
        }

        return "No cat fact available at the moment.";
    }

    // Inner class to match the Cat Fact API response
    private static class CatFactResponse {
        private String fact;

        public String getFact() {
            return fact;
        }

        public void setFact(String fact) {
            this.fact = fact;
        }
    }
}
