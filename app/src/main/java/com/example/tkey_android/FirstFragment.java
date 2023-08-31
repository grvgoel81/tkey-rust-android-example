package com.example.tkey_android;
import android.content.Context;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.navigation.fragment.NavHostFragment;

import com.example.tkey_android.databinding.FragmentFirstBinding;
import com.web3auth.tkey.RuntimeError;
import com.web3auth.tkey.ThresholdKey.Common.KeyPoint;
import com.web3auth.tkey.ThresholdKey.Common.PrivateKey;
import com.web3auth.tkey.ThresholdKey.Common.Result;
import com.web3auth.tkey.ThresholdKey.KeyDetails;
import com.web3auth.tkey.ThresholdKey.Modules.TSSModule;
import com.web3auth.tkey.ThresholdKey.RssComm;
import com.web3auth.tkey.ThresholdKey.ServiceProvider;
import com.web3auth.tkey.ThresholdKey.StorageLayer;
import com.web3auth.tkey.ThresholdKey.ThresholdKey;

import org.json.JSONObject;
import org.torusresearch.customauth.CustomAuth;
import org.torusresearch.customauth.types.Auth0ClientOptions.Auth0ClientOptionsBuilder;
import org.torusresearch.customauth.types.CustomAuthArgs;
import org.torusresearch.customauth.types.LoginType;
import org.torusresearch.customauth.types.NoAllowedBrowserFoundException;
import org.torusresearch.customauth.types.SubVerifierDetails;
import org.torusresearch.customauth.types.TorusLoginResponse;
import org.torusresearch.customauth.types.UserCancelledException;
import org.torusresearch.customauth.utils.Helpers;
import org.torusresearch.fetchnodedetails.types.TorusNetwork;
// fetch node details
import org.torusresearch.fetchnodedetails.FetchNodeDetails;
import org.torusresearch.fetchnodedetails.types.NodeDetails;
// torus utils
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.types.SessionToken;
import org.torusresearch.torusutils.types.TorusCtorOptions;


import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.SecretKey;

public class FirstFragment extends Fragment {

    private static final String GOOGLE_CLIENT_ID = "221898609709-obfn3p63741l5333093430j3qeiinaa8.apps.googleusercontent.com";
    private static final String GOOGLE_VERIFIER = "google-lrc";
    private FragmentFirstBinding binding;
    private LoginVerifier selectedLoginVerifier;
    private CustomAuth torusSdk;
    private static final String PREF_NAME = "TKEY";
    private static final String STRING_KEY = "FactorKey";

    private final String[] allowedBrowsers = new String[]{
            "com.android.chrome", // Chrome stable
            "com.google.android.apps.chrome", // Chrome system
            "com.android.chrome.beta", // Chrome beta
    };

    @Override
    public View onCreateView(
            @NonNull LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState
    ) {
        binding = FragmentFirstBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    private void showLoading() {
        requireActivity().runOnUiThread(() -> {
            ProgressBar pb = binding.loadingIndicator;
            pb.setVisibility(View.VISIBLE);
        });
    }

    private void hideLoading() {
        requireActivity().runOnUiThread(() -> {
            ProgressBar pb = binding.loadingIndicator;
            pb.setVisibility(View.GONE);
        });
    }

    public void onViewCreated(@NonNull View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        MainActivity activity = ((MainActivity) requireActivity());

        userHasNotLoggedInWithGoogle();

        CustomAuthArgs args = new CustomAuthArgs(
                "https://scripts.toruswallet.io/redirect.html",
                TorusNetwork.SAPPHIRE_DEVNET,
                "torusapp://org.torusresearch.customauthandroid/redirect",
                "BG4pe3aBso5SjVbpotFQGnXVHgxhgOxnqnNBKyjfEJ3izFvIVWUaMIzoCrAfYag8O6t6a6AOvdLcS4JR2sQMjR4"
        );
        args.setEnableOneKey(true);

        // Initialize CustomAuth
        this.torusSdk = new CustomAuth(args, activity);


        binding.textviewFirst.setOnClickListener(view1 -> NavHostFragment.findNavController(FirstFragment.this)
                .navigate(R.id.action_FirstFragment_to_SecondFragment));

        binding.googleLogin.setOnClickListener(view1 -> {
            showLoading();
            try {
                selectedLoginVerifier = new LoginVerifier("Google", LoginType.GOOGLE, GOOGLE_CLIENT_ID, GOOGLE_VERIFIER);

                Auth0ClientOptionsBuilder builder = null;
                if (selectedLoginVerifier.getDomain() != null) {
                    builder = new Auth0ClientOptionsBuilder(selectedLoginVerifier.getDomain());
                    builder.setVerifierIdField(selectedLoginVerifier.getVerifierIdField());
                    builder.setVerifierIdCaseSensitive(selectedLoginVerifier.isVerfierIdCaseSensitive());
                }
                CompletableFuture<TorusLoginResponse> torusLoginResponseCf;
                if (builder == null) {
                    torusLoginResponseCf = torusSdk.triggerLogin(
                            new SubVerifierDetails(selectedLoginVerifier.getTypeOfLogin(),
                            selectedLoginVerifier.getVerifier(),
                            selectedLoginVerifier.getClientId())
                            .setPreferCustomTabs(true)
                            .setAllowedBrowsers(allowedBrowsers));
                } else {
                    torusLoginResponseCf = torusSdk.triggerLogin(new SubVerifierDetails(
                            selectedLoginVerifier.getTypeOfLogin(),
                            selectedLoginVerifier.getVerifier(),
                            selectedLoginVerifier.getClientId(),
                            builder.build())
                            .setPreferCustomTabs(true)
                            .setAllowedBrowsers(allowedBrowsers));
                }

                torusLoginResponseCf.whenCompleteAsync((torusLoginResponse, error) -> {
                    if (error != null) {
                        renderError(error);
                        hideLoading();
                    } else {
                        activity.runOnUiThread(() -> {
                            String publicAddress = torusLoginResponse.getPublicAddress();
                            activity.postboxKey = torusLoginResponse.getPrivateKey().toString(16);
                            activity.userInfo = torusLoginResponse.getUserInfo();
                            activity.sessionData = torusLoginResponse.getRetrieveSharesResponse().getSessionData();
                            binding.resultView.append("postboxKey: " + activity.postboxKey);
                            binding.resultView.append("publicKey: " + activity.postboxKey);
                            userHasLoggedInWithGoogle();
                            hideLoading();
                        });

                    }
                });
            } catch (Exception e) {
                renderError(e);
            }
        });

        binding.tKeyMPC.setOnClickListener(view1 -> {
            try {

                showLoading();

                // prepare tkey parameters
                String verifierId = activity.userInfo.getVerifierId();
                String verifier = activity.userInfo.getVerifier();

                List<SessionToken> sessionTokenData = activity.sessionData.getSessionTokenData();
                ArrayList<String> signatureString = new ArrayList<>();
                for (SessionToken item : sessionTokenData) {
                    if (item != null) {
                        JSONObject temp = new JSONObject();
                        temp.put("data", item.getToken());
                        temp.put("sig", item.getSignature());
                        signatureString.add(temp.toString());
                    }
                }

                // node details
                FetchNodeDetails nodeManager = new FetchNodeDetails(TorusNetwork.SAPPHIRE_DEVNET);
                CompletableFuture<NodeDetails> nodeDetailResult = nodeManager.getNodeDetails(verifier, verifierId);
                NodeDetails nodeDetail = nodeDetailResult.get();

                // Torus Utils
                TorusCtorOptions torusOptions = new TorusCtorOptions("Custom");
                torusOptions.setNetwork(TorusNetwork.SAPPHIRE_DEVNET.toString());
                torusOptions.setClientId("BG4pe3aBso5SjVbpotFQGnXVHgxhgOxnqnNBKyjfEJ3izFvIVWUaMIzoCrAfYag8O6t6a6AOvdLcS4JR2sQMjR4");
                TorusUtils torusUtils = new TorusUtils(torusOptions);
                String[] tssEndpoint = nodeDetail.getTorusNodeTSSEndpoints();

                // storage layer and service provider
                activity.transferStorage = new StorageLayer(true, "https://metadata.tor.us", 2);
                activity.transferProvider = new ServiceProvider(true, activity.postboxKey,true, verifier, verifierId, nodeDetail);

                // Threshold initialization
                RssComm rss_comm = new RssComm();
                activity.transferKey = new ThresholdKey(null, null, activity.transferStorage, activity.transferProvider, null, null, true, false, rss_comm);

                CountDownLatch lock = new CountDownLatch(1);
                activity.transferKey.initialize(activity.postboxKey, null, false, false, false, false, null, 0, null, result -> {
                    if (result instanceof Result.Error) {
                        throw new RuntimeException("Could not initialize tkey");
                    }
                    lock.countDown();
                });
                lock.await();
                KeyDetails keyDetails = activity.transferKey.getKeyDetails();

                String metadataPublicKey = keyDetails.getPublicKeyPoint().getPublicKey(KeyPoint.PublicKeyEncoding.EllipticCompress);

                // existing or new user check
                if(keyDetails.getRequiredShares() > 0) {
                    // existing user
                    ArrayList<String> allTags = TSSModule.getAllTSSTags(activity.transferKey);
                    String tag = "default"; // allTags[0]
                    String fetchId = metadataPublicKey + ":" + tag + ":0";

                    // fetch key from keystore and assign it to factorKey
                    String factorKey = "";
                    String retrievedKey = getStringFromSharedPreferences();

                    if (retrievedKey != null) {
                        factorKey = retrievedKey;
                    } else {
                        throw new Exception("factor key not found in storage");
                    }

                    // input factor key from key store
                    CountDownLatch lock2 = new CountDownLatch(1);
                    activity.transferKey.inputFactorKey(factorKey, result -> {
                        if (result instanceof Result.Error) {
                            throw new RuntimeException("Could not inputFactorKey for tkey");
                        }
                        lock2.countDown();
                    });
                    lock2.await();
                    PrivateKey pk = new PrivateKey(factorKey);
                    String deviceFactorPub = pk.toPublic(KeyPoint.PublicKeyEncoding.FullAddress);

                    // reconstruct and getTssPubKey
                    CountDownLatch lock3 = new CountDownLatch(2);
                    activity.transferKey.reconstruct(result -> {
                        if (result instanceof Result.Error) {
                            throw new RuntimeException("Could not reconstruct tkey");
                        }
                        lock3.countDown();
                    });
                    KeyDetails keyDetails2 = activity.transferKey.getKeyDetails();

                    AtomicReference<String> pubKey = new AtomicReference<>("");
                    TSSModule.getTSSPubKey(activity.transferKey, tag, result -> {
                        if (result instanceof Result.Error) {
                            throw new RuntimeException("Could not getTSSPubKey tkey");
                        }
                        pubKey.set(((Result.Success<String>) result).data);
                        lock3.countDown();
                    });
                    lock3.await();

                    HashMap<String, ArrayList<String>> defaultTssShareDescription = activity.transferKey.getShareDescriptions();
                    // todo: check if we need to format this
                } else {
                    // new user
                    // check if reconstruction is working before creating tagged share
                    CountDownLatch lock4 = new CountDownLatch(1);
                    int requiredShares = keyDetails.getRequiredShares();
                    activity.transferKey.reconstruct(result -> {
                        if (result instanceof Result.Error) {
                            String errorMsg = "Failed to reconstruct key" + requiredShares  + " more share(s) required. If you have security question share, we suggest you to enter security question PW to recover your account";
                            throw new RuntimeException(errorMsg);
                        }
                        lock4.countDown();
                    });
                    lock4.await();

                    // create tagged tss share
                    PrivateKey factorKey = PrivateKey.generate();
                    String factorPub = factorKey.toPublic(KeyPoint.PublicKeyEncoding.FullAddress);
                    String defaultTag = "default";

                    renderTKeyText("factorPub", factorPub);
                    CountDownLatch lock5 = new CountDownLatch(1);
                    TSSModule.createTaggedTSSTagShare(activity.transferKey, defaultTag, null, factorPub, 2, nodeDetail, torusUtils, result -> {
                        if (result instanceof Result.Error) {
                            throw new RuntimeException("Could not createTaggedTSSTagShare tkey");
                        }
                        lock5.countDown();
                    });
                    lock5.await();

                    CountDownLatch lock12 = new CountDownLatch(1);
                    AtomicReference<String> pubKeyNew = new AtomicReference<>("");
                    TSSModule.getTSSPubKey(activity.transferKey, defaultTag, result -> {
                        if (result instanceof Result.Error) {
                            throw new RuntimeException("Could not getTSSPubKey tkey");
                        }
                        pubKeyNew.set(((Result.Success<String>) result).data);
                        lock12.countDown();
                    });
                    lock12.await();

                    // backup share with input factor key
                    ArrayList<String> shareIndexes = activity.transferKey.getShareIndexes();
                    shareIndexes.removeIf(index -> index.equals("1"));
                    TSSModule.backupShareWithFactorKey(activity.transferKey, shareIndexes.get(0), factorKey.hex);

                    // add share description
                    CountDownLatch lock6 = new CountDownLatch(1);
                    JSONObject description = new JSONObject();
                    description.put("module", "Device Factor key");
                    description.put("tssTag", defaultTag);
                    description.put("tssShareIndex", 2);
                    description.put("dateAdded", System.currentTimeMillis()/1000);
                    activity.transferKey.addShareDescription(shareIndexes.get(0), description.toString(), true, result -> {
                        if (result instanceof Result.Error) {
                            throw new RuntimeException("Could not add share description for tkey");
                        }
                        lock6.countDown();
                    });
                    lock6.await();

                    saveStringToSharedPreferences(factorKey.hex);

                    System.out.println("factorKey");
                    System.out.println(factorKey.hex);

                    // reconstruction
                    CountDownLatch lock7 = new CountDownLatch(1);
                    activity.transferKey.reconstruct(result -> {
                        if (result instanceof Result.Error) {
                            String errorMsg = "Failed to reconstruct key" + requiredShares  + " more share(s) required. If you have security question share, we suggest you to enter security question PW to recover your account";
                            throw new RuntimeException(errorMsg);
                        }
                        lock7.countDown();
                    });
                    lock7.await();
                }

                HashMap<String, ArrayList<String>> shareDescriptions = activity.transferKey.getShareDescriptions();
                // disable button
                userHasCreatedTkey();
                hideLoading();
                binding.resultView.append("Log: \n");
                binding.resultView.append("Tkey Creaetion Successfull" + "\n");
            } catch (Exception | RuntimeError e) {
                hideLoading();
                renderError(e);
            }
        });
    }

    // Fetch a key by alias
    private static SecretKey getKey(KeyStore keyStore, String alias, char[] password) throws KeyStoreException, KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        if (keyStore.containsAlias(alias)) {
            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(password));
            return (SecretKey) entry.getSecretKey();
        }
        return null;
    }

    // Set a key in the keystore
    private static void setKey(KeyStore keyStore, String alias, byte[] keyBytes, char[] password) throws KeyStoreException {
        SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
        keyStore.setEntry(alias, new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection(password));
    }

    private void saveStringToSharedPreferences(String data) {
        SharedPreferences sharedPreferences = getActivity().getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString(STRING_KEY, data);
        editor.apply();
    }

    private String getStringFromSharedPreferences() {
        SharedPreferences sharedPreferences = getActivity().getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return sharedPreferences.getString(STRING_KEY, null);
    }

    private void renderError(Throwable error) {
        requireActivity().runOnUiThread(() -> {
            Throwable reason = Helpers.unwrapCompletionException(error);
            TextView textView = binding.resultView;
            if (reason instanceof UserCancelledException || reason instanceof NoAllowedBrowserFoundException) {
                textView.setText(error.getMessage());
            } else {
                String errorMessage = getResources().getString(R.string.error_message, error.getMessage());
                textView.setText(errorMessage);
            }
        });
    }

    private void userHasNotLoggedInWithGoogle() {
        requireActivity().runOnUiThread(() -> {
            binding.googleLogin.setEnabled(true);
            binding.tKeyMPC.setEnabled(false);
        });
    }

    private void userHasLoggedInWithGoogle() {
        requireActivity().runOnUiThread(() -> {
            binding.googleLogin.setEnabled(false);
            binding.tKeyMPC.setEnabled(true);
        });
    }

    private void userHasCreatedTkey() {
        MainActivity activity = (MainActivity) requireActivity();
        requireActivity().runOnUiThread(() -> {
            binding.googleLogin.setEnabled(false);
            binding.tKeyMPC.setEnabled(false);
        });
    }

    private void renderTKeyText(String heading, String details) {
        requireActivity().runOnUiThread(() -> {
            binding.resultView.setText("");
            binding.resultView.append("Log: \n");
            binding.resultView.append(heading + "\n");
            binding.resultView.append(details + "\n");
        });
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }

}