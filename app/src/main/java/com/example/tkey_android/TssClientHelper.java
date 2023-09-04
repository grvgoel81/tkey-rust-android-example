package com.example.tkey_android;

import android.content.Context;
import android.content.DialogInterface;
import android.util.Pair;

import androidx.appcompat.app.AlertDialog;

import com.web3auth.tkey.RuntimeError;
import com.web3auth.tkey.ThresholdKey.Common.KeyPoint;
import com.web3auth.tss_client_android.client.Delimiters;
import com.web3auth.tss_client_android.client.EndpointsData;
import com.web3auth.tss_client_android.client.TSSClient;
import com.web3auth.tss_client_android.client.TSSHelpers;
import com.web3auth.tss_client_android.client.util.Secp256k1;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class TssClientHelper {
    public static Pair<TSSClient, Map<String, String>> helperTssClient(String selectedTag, int tssNonce, String publicKey, String tssShare, String tssIndex, List<BigInteger> nodeIndexes, String factorKey, String verifier, String verifierId, List<String> tssEndpoints) throws Exception, RuntimeError {
        BigInteger randomKey = new BigInteger(1, Secp256k1.GenerateECKey());
        BigInteger random = randomKey.add(BigInteger.valueOf(System.currentTimeMillis() / 1000));
        String sessionNonce = //random.toString(); //TSSHelpers.hashMessage(random.toString(16));
                TSSHelpers.base64ToBase64url(TSSHelpers.hashMessage(random.toByteArray().toString()));
        String session = TSSHelpers.assembleFullSession(verifier, verifierId, selectedTag, Integer.toString(tssNonce), sessionNonce);

        System.out.println("PublicKey: " + publicKey);
        System.out.println("TssIndex: " + tssIndex);

        BigInteger userTssIndex = new BigInteger(tssIndex, 16);
        int parties = 4;
        int clientIndex = parties - 1;

        EndpointsData endpointsData = generateEndpoints(parties, clientIndex, tssEndpoints);
        List<String> endpoints = endpointsData.getEndpoints();
        List<String> socketUrls = endpointsData.getTssWSEndpoints();
        List<Integer> partyIndexes = endpointsData.getPartyIndexes();
        List<BigInteger> nodeInd = new ArrayList<>();
        nodeInd.add(new BigInteger("1"));
        nodeInd.add(new BigInteger("2"));
        nodeInd.add(new BigInteger("3"));

        Map<String, String> coeffs = TSSHelpers.getServerCoefficients(nodeInd.toArray(new BigInteger[0]), userTssIndex);

        BigInteger shareUnsigned = new BigInteger(tssShare, 16);
        BigInteger share = shareUnsigned;
        System.out.println("Share: " + share);
        System.out.println("ClientIndex: " + clientIndex);
        String uncompressedPubKey = new KeyPoint(publicKey).getPublicKey(KeyPoint.PublicKeyEncoding.FullAddress);
        System.out.println("UncompressedPubKey: "+ uncompressedPubKey);

        TSSClient client = new TSSClient(session, clientIndex, partyIndexes.stream().mapToInt(Integer::intValue).toArray(),
                endpoints.toArray(new String[0]), socketUrls.toArray(new String[0]), TSSHelpers.base64Share(share),
                TSSHelpers.base64PublicKey(hexStringToByteArray(uncompressedPubKey)));

        System.out.println("Session: "+ session);
        System.out.println("ClientIndex: "+ clientIndex);
        System.out.println("Parties: " + Arrays.toString(partyIndexes.stream().mapToInt(Integer::intValue).toArray()));
        System.out.println("Endpoints: " + Arrays.toString(endpoints.toArray(new String[0])));
        System.out.println("TssSocketEndpoints: " + Arrays.toString(socketUrls.toArray(new String[0])));
        System.out.println("Share: " + TSSHelpers.base64Share(share));
        System.out.println("PubKey: "+ TSSHelpers.base64PublicKey(hexStringToByteArray(uncompressedPubKey)));
        System.out.println("socketSession: " + session.split(Delimiters.Delimiter4)[1]);

        System.out.println("ServerCoeffs: " + coeffs);

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

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        System.out.println("after conversion byte array: " + data + "length: " + data.length);
        return data;
    }

    public static EndpointsData generateEndpoints(int parties, int clientIndex, List<String> tssEndpoints) {
        List<String> endpoints = new ArrayList();
        List<String> tssWSEndpoints = new ArrayList();
        List<Integer> partyIndexes = new ArrayList();

        for(int i = 0; i < parties; ++i) {
            partyIndexes.add(i);
            if (i == clientIndex) {
                endpoints.add(null);
                tssWSEndpoints.add(null);
            } else {
                endpoints.add(tssEndpoints.get(i));
                tssWSEndpoints.add(tssEndpoints.get(i).replace("/tss", ""));
            }
        }

        return new EndpointsData(endpoints, tssWSEndpoints, partyIndexes);
    }

    public static void showAlert(final Context context, final String message)
    {
        AlertDialog.Builder alertbox = new AlertDialog.Builder(context);
        alertbox.setCancelable(false);
        alertbox.setMessage(message);
        alertbox.setNeutralButton("OK", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
            }
        });

        alertbox.show();
    }
}
