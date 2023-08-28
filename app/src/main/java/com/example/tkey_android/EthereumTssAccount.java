package com.example.tkey_android;

import android.util.Pair;

import com.web3auth.tkey.RuntimeError;
import com.web3auth.tss_client_android.client.TSSClient;
import com.web3auth.tss_client_android.client.TSSHelpers;
import com.web3auth.tss_client_android.client.util.Triple;
import com.web3auth.tss_client_android.dkls.Precompute;

import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.Sign;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class EthereumTssAccount extends Sign {
    public String selectedTag;
    public String verifier;
    public String factorKey;
    public String verifierID;
    public String publicKey;
    public List<String> authSigs;
    public int tssNonce;
    public String tssShare;
    public String tssIndex;
    public BigInteger[] nodeIndexes;
    public String[] tssEndpoints;
    public String address;

    public EthereumTssAccount(String evmAddress, String pubkey, String factorKey, int tssNonce, String tssShare, String tssIndex,
                              String selectedTag, String verifier, String verifierID, BigInteger[] nodeIndexes,
                              String[] tssEndpoints, List<String> authSigs) throws Exception {
        this.factorKey = factorKey;
        this.selectedTag = selectedTag;
        this.verifier = verifier;
        this.verifierID = verifierID;
        this.publicKey = pubkey;
        this.nodeIndexes = nodeIndexes;
        this.tssEndpoints = tssEndpoints;
        this.tssNonce = tssNonce;
        this.tssIndex = tssIndex;
        this.tssShare = tssShare;
        this.address = evmAddress;
        this.authSigs = authSigs;
    }

    public String sign(RawTransaction transaction) {
        // Create tss Client using helper
        TSSClient client;
        Map<String, String> coeffs;
        try {
            Pair<TSSClient, Map<String, String>> clientCoeffsPair = TssClientHelper.helperTssClient(this.selectedTag, this.tssNonce, this.publicKey, this.tssShare, this.tssIndex,
                    Arrays.asList(this.nodeIndexes), this.factorKey, this.verifier, this.verifierID, Arrays.asList(this.tssEndpoints));
            client = clientCoeffsPair.first;
            coeffs = clientCoeffsPair.second;
        } catch (Exception e) {
            throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
        } catch (RuntimeError e) {
            throw new RuntimeException(e);
        }

        // Wait for sockets to be connected
        boolean connected;
        try {
            connected = client.checkConnected();
        } catch (Exception e) {
            throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
        }

        if (!connected) {
            throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
        }

        Precompute precompute;
        try {
            precompute = client.precompute((Map<String, String>) coeffs, this.authSigs);
        } catch (Exception e) {
            throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
        }

        boolean ready;
        try {
            ready = client.isReady();
        } catch (Exception e) {
            throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
        }

        if (!ready) {
            throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
        }

        //to check
        if (transaction.getData() == null) {
            throw new EthereumSignerError(EthereumSignerError.ErrorType.EMPTY_RAW_TRANSACTION);
        }

        //to check
        String msgData = TSSHelpers.hashMessage(transaction.getData());
        //byte[] msgData = Hash.keccak256(transaction.raw);
        String signingMessage = null;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            signingMessage = Base64.getEncoder().encodeToString(msgData.getBytes(StandardCharsets.UTF_8));
        }
        Triple<BigInteger, BigInteger, Byte> signatureResult;
        try {
            signatureResult = client.sign(signingMessage, true, null, precompute, this.authSigs);
        } catch (Exception e) {
            throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
        }

        try {
            client.cleanup(authSigs.toArray(new String[0]));
        } catch (Exception e) {
            // Do nothing or handle cleanup failure
        }

        String signature = TSSHelpers.hexSignature(signatureResult.getFirst(), signatureResult.getSecond(), signatureResult.getThird());
        //return new SignedTransaction(transaction, signature);
        return signature;
    }
}

