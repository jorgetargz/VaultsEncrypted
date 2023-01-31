package org.jorgetargz.client.dao.di;

import com.google.gson.*;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import java.time.LocalDate;
import java.time.LocalDateTime;

public class ProducerGson {

    @Singleton
    @Produces
    public Gson getGson() {
        return new GsonBuilder().registerTypeAdapter(LocalDateTime.class,
                (JsonDeserializer<LocalDateTime>) (json, type, jsonDeserializationContext) -> LocalDateTime.parse(json.getAsJsonPrimitive().getAsString().substring(0, 16))).registerTypeAdapter(LocalDateTime.class,
                (JsonSerializer<LocalDateTime>) (localDateTime, type, jsonSerializationContext) -> new JsonPrimitive(localDateTime.toString())
        ).registerTypeAdapter(LocalDate.class,
                (JsonDeserializer<LocalDate>) (json, type, jsonDeserializationContext) -> LocalDate.parse(json.getAsJsonPrimitive().getAsString())).registerTypeAdapter(LocalDate.class,
                (JsonSerializer<LocalDate>) (localDate, type, jsonSerializationContext) -> new JsonPrimitive(localDate.toString())
        ).create();
    }
}
