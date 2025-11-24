package com.example.demo.app;

import com.example.demo.core.CoreService;

public class App {
    public static void main(String[] args) {
        CoreService service = new CoreService();
        System.out.println(service.sayHello("world"));
    }
}
