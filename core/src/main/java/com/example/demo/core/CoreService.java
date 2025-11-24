package com.example.demo.core;

import org.apache.commons.lang3.StringUtils;

public class CoreService {
    public String sayHello(String name) {
        return "Hello, " + StringUtils.capitalize(name) + "!";
    }
}
