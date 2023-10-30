package com.speculatingwook.OauthSpringBoot.global.utils;

import lombok.Getter;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Getter
public class DateTimeUtil {

    private final LocalDateTime now;
    private final DateTimeFormatter dateTimeFormatter;
    public DateTimeUtil() {
        this.now = LocalDateTime.now();
        this.dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
    }
}