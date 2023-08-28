package com.example.tkey_android;

public class CustomError extends Error {
    private ErrorType errorType;

    public CustomError(ErrorType errorType) {
        this.errorType = errorType;
    }

    public String getErrorDescription() {
        switch (errorType) {
            case UNKNOWN_ERROR:
                return "unknownError";
            case METHOD_UNAVAILABLE:
                return "method unavailable/unimplemented";
            default:
                return "unknown error";
        }
    }

    public enum ErrorType {
        UNKNOWN_ERROR,
        METHOD_UNAVAILABLE
    }
}
