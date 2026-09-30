package com.sozureke.auth_server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.GenericJacksonJsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

@Configuration
public class RedisSessionConfig {

  @Bean
  public CookieSerializer cookieSerializer(
      @Value("${app.session.cookie.name:SESSION}") String name,
      @Value("${app.session.cookie.same-site:Lax}") String sameSite,
      @Value("${app.session.cookie.secure:false}") boolean secure) {
    DefaultCookieSerializer serializer = new DefaultCookieSerializer();
    serializer.setCookieName(name);
    serializer.setUseHttpOnlyCookie(true);
    serializer.setSameSite(sameSite);
    if (secure) {
      serializer.setUseSecureCookie(true);
    }
    return serializer;
  }

  @Bean
  public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
    BasicPolymorphicTypeValidator.Builder ptv =
        BasicPolymorphicTypeValidator.builder()
            .allowIfSubType("com.sozureke.auth_server")
            .allowIfSubType("java.lang")
            .allowIfSubType("java.util")
            .allowIfSubType("java.time")
            .allowIfSubType("org.springframework.security")
            .allowIfSubTypeIsArray();
    JsonMapper mapper =
        JsonMapper.builder()
            .addModules(SecurityJacksonModules.getModules(getClass().getClassLoader(), ptv))
            .build();
    return new GenericJacksonJsonRedisSerializer(mapper);
  }
}
