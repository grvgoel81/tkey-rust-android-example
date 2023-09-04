package com.example.tkey_android;

public class EthereumSignerError extends Error {
    private ErrorType errorType;

    public EthereumSignerError(ErrorType errorType) {
        this.errorType = errorType;
    }

    public String getErrorDescription() {
        switch (errorType) {
            case EMPTY_RAW_TRANSACTION:
                return "emptyRawTransaction";
            case UNKNOWN_ERROR:
                return "unknownError";
            default:
                return "unknown error";
        }
    }

    public enum ErrorType {
        EMPTY_RAW_TRANSACTION,
        UNKNOWN_ERROR
    }
}

