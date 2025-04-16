package com.example.practice_ss.constans;

public enum Paths {
    CONTACTS("/contact"),
    NOTICES("/notices"),
    MY_ACCOUNT("/myAccount"),
    MY_BALANCE("/myBalance"),
    MY_LOANS("/myLoans"),
    MY_CARDS("/myCards"),
    H2_CONSOLE("/h2-console/**"),
    USER("/user/**"),
    LOGIN("/login"),
    GET_TOKEN("/token");

    private final String path;

    Paths(String path) {
        this.path = path;
    }

    public String toString(){
        return this.path;
    }
}
