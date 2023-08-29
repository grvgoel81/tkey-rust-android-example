package com.example.tkey_android;

import android.util.Pair;

import com.web3auth.tkey.RuntimeError;
import com.web3auth.tkey.ThresholdKey.Common.KeyPoint;
import com.web3auth.tss_client_android.client.EndpointsData;
import com.web3auth.tss_client_android.client.TSSClient;
import com.web3auth.tss_client_android.client.TSSHelpers;
import com.web3auth.tss_client_android.client.util.Secp256k1;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

public class TssClientHelper {
    public static Pair<TSSClient, Map<String, String>> helperTssClient(String selectedTag, int tssNonce, String publicKey, String tssShare, String tssIndex, List<BigInteger> nodeIndexes, String factorKey, String verifier, String verifierId, List<String> tssEndpoints) throws Exception, RuntimeError {
        BigInteger randomKey = new BigInteger(1, Secp256k1.GenerateECKey());
        BigInteger random = randomKey.add(BigInteger.valueOf(System.currentTimeMillis() / 1000));
        String sessionNonce = TSSHelpers.hashMessage(random.toString(16));
        String session = TSSHelpers.assembleFullSession(verifier, verifierId, selectedTag, Integer.toString(tssNonce), sessionNonce);

        BigInteger userTssIndex = new BigInteger(tssIndex, 16);
        int parties = 4;
        int clientIndex = parties - 1;

        EndpointsData endpointsData = TSSHelpers.generateEndpoints(parties, clientIndex);
        List<String> endpoints = endpointsData.getEndpoints();
        List<String> socketUrls = endpointsData.getTssWSEndpoints();
        List<Integer> partyIndexes = endpointsData.getPartyIndexes();
        List<BigInteger> nodeInd = nodeIndexes;

        Map<String, String> coeffs = TSSHelpers.getServerCoefficients(nodeInd.toArray(new BigInteger[0]), userTssIndex);

        BigInteger shareUnsigned = new BigInteger(tssShare, 16);
        BigInteger share = shareUnsigned;

        String uncompressedPubKey = new KeyPoint(publicKey).getPublicKey(KeyPoint.PublicKeyEncoding.FullAddress);

        TSSClient client = new TSSClient(session, clientIndex, partyIndexes.stream().mapToInt(Integer::intValue).toArray(),
                endpoints.toArray(new String[0]), socketUrls.toArray(new String[0]), TSSHelpers.base64Share(share),
                TSSHelpers.base64PublicKey(convertToBytes(uncompressedPubKey)));

        return new Pair<>(client, coeffs);
    }

    public static byte[] convertToBytes (String s) {
        String tmp;
        byte[] b = new byte[s.length() / 2];
        int i;
        for (i = 0; i < s.length() / 2; i++) {
            tmp = s.substring(i * 2, i * 2 + 2);
            b[i] = (byte)(Integer.parseInt(tmp, 16) & 0xff);
        }
        return b;
    }
}
