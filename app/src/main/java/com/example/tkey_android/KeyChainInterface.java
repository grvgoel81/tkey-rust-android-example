package com.example.tkey_android;

import android.os.Build;

import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class KeyChainInterface {
    private EnCryptor encryptor;
    private DeCryptor decryptor;

    KeyChainInterface() {
        encryptor = new EnCryptor();

        try {
            decryptor = new DeCryptor();
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException |
                 IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    void save(String alias, String textToSave) {
        try {
            encryptor.encryptText(alias, textToSave);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | NoSuchProviderException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    String fetch(String alias) {
        try {
            return decryptor.decryptData(alias, encryptor.getEncryption(), encryptor.getIv());
        } catch ( UnrecoverableEntryException | KeyStoreException | NoSuchPaddingException | NoSuchAlgorithmException | UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
//            throw new RuntimeException(e);
            return null;
        }
    }

    void deleteEntry(String alias) {
        try {
            decryptor.deleteEntry(alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
}
