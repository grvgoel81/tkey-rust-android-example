package com.example.tkey_android;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import android.util.Pair;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.navigation.fragment.NavHostFragment;

import com.example.tkey_android.databinding.FragmentFirstBinding;
import com.google.android.material.snackbar.Snackbar;
import com.google.gson.Gson;
import com.web3auth.tkey.RuntimeError;
import com.web3auth.tkey.ThresholdKey.Common.KeyPoint;
import com.web3auth.tkey.ThresholdKey.Common.PrivateKey;
import com.web3auth.tkey.ThresholdKey.Common.Result;
import com.web3auth.tkey.ThresholdKey.KeyDetails;
import com.web3auth.tkey.ThresholdKey.KeyReconstructionDetails;
import com.web3auth.tkey.ThresholdKey.Modules.TSSModule;
import com.web3auth.tkey.ThresholdKey.RssComm;
import com.web3auth.tkey.ThresholdKey.ServiceProvider;
import com.web3auth.tkey.ThresholdKey.StorageLayer;
import com.web3auth.tkey.ThresholdKey.ThresholdKey;
import com.web3auth.tss_client_android.client.TSSClient;
import com.web3auth.tss_client_android.client.TSSClientError;
import com.web3auth.tss_client_android.client.TSSHelpers;
import com.web3auth.tss_client_android.client.util.Triple;
import com.web3auth.tss_client_android.dkls.Precompute;

import org.json.JSONException;
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
import org.torusresearch.fetchnodedetails.FetchNodeDetails;
import org.torusresearch.fetchnodedetails.types.NodeDetails;
import org.torusresearch.fetchnodedetails.types.TorusNetwork;
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.types.SessionToken;
import org.torusresearch.torusutils.types.TorusCtorOptions;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.Sign;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthGasPrice;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicReference;

public class FirstFragment extends Fragment {

    private static final String GOOGLE_CLIENT_ID = "221898609709-obfn3p63741l5333093430j3qeiinaa8.apps.googleusercontent.com";
    private static final String GOOGLE_VERIFIER = "google-lrc";
    private FragmentFirstBinding binding;
    private LoginVerifier selectedLoginVerifier;
    private CustomAuth torusSdk;

    static {
        System.loadLibrary("dkls-native");
    }

    private static final String PREF_NAME = "TKEY";
    private static final String STRING_KEY = "FactorKey";

    private final String[] allowedBrowsers = new String[]{
            "com.android.chrome", // Chrome stable
            "com.google.android.apps.chrome", // Chrome system
            "com.android.chrome.beta", // Chrome beta
    };

    //    To be used for saving/reading data from shared prefs
    private final String SHARE_ALIAS = "SHARE";
    private final String SHARE_INDEX_ALIAS = "SHARE_INDEX";
    private final String SHARE_INDEX_GENERATED_ALIAS = "SHARE_INDEX_GENERATED_ALIAS";
    private final String ADD_PASSWORD_SET_ALIAS = "ADD_PASSWORD_SET_ALIAS";

    private final String SEED_PHRASE_SET_ALIAS = "SEED_PHRASE_SET_ALIAS";
    private final String SEED_PHRASE_ALIAS = "SEED_PHRASE_ALIAS";

    private String REQUEST_ID = "";

    private String factor_key = "";
    private int tssNonce;
    private String tssShare = "";
    private String tssIndex = "";
    private String verifierId = "";
    private String verifier = "";
    private NodeDetails nodeDetail;
    private String evmAddress;
    private AtomicReference<String> pubKey = new AtomicReference<>("");
    private ArrayList<String> signatureString;
    private Pair<String, String> tssShareResponse = new Pair<>("", "");
    private Gson gson = new Gson();
    private String fullTssPubKey;

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
                    torusLoginResponseCf = torusSdk.triggerLogin(new SubVerifierDetails(selectedLoginVerifier.getTypeOfLogin(),
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
                            binding.resultView.append("publicAddress: " + publicAddress);
                            userHasLoggedInWithGoogle();
                            hideLoading();
                        });

                    }
                });
            } catch (Exception e) {
                renderError(e);
            }
        });

//        binding.requestNewShare.setOnClickListener(view1 -> {
//            try {
//                activity.transferStorage = new StorageLayer(false, "https://metadata.tor.us", 2);
//                activity.transferProvider =   new ServiceProvider(true, activity.postboxKey,true, verifier, verifierId, nodeDetail);
//                activity.transferKey = new ThresholdKey(null, null, activity.transferStorage, activity.transferProvider, null, null, false, false);
//                activity.transferKey.initialize(null, null, false, false, result -> {
//                    if (result instanceof Result.Error) {
//                        Exception e = ((Result.Error<KeyDetails>) result).exception;
//                        renderError(e);
//                    } else if (result instanceof Result.Success) {
//                        requireActivity().runOnUiThread(() -> {
//                            String userAgent = new WebView(getContext()).getSettings().getUserAgentString();
//                            SharetransferModule.requestNewShare(activity.transferKey, userAgent, "[]", (result1) -> {
//                                if (result1 instanceof Result.Error) {
//                                    renderError(((Result.Error<String>) result1).exception);
//                                } else if (result1 instanceof Result.Success) {
//                                    String requestId = ((Result.Success<String>) result1).data;
//                                    REQUEST_ID = requestId;
//                                    requireActivity().runOnUiThread(() -> {
//                                        Snackbar snackbar = Snackbar.make(view1, "Request Id: " + requestId, Snackbar.LENGTH_LONG);
//                                        snackbar.show();
//                                        binding.requestNewShare.setEnabled(false);
//                                        binding.lookForRequests.setEnabled(true);
//                                        binding.cleanupRequests.setEnabled(true);
//                                    });
//                                }
//                            });
//                        });
//                    }
//                });
//            } catch (RuntimeError | JSONException e) {
//                renderError(e);
//            }
//        });

        binding.createThresholdKey.setOnClickListener(view1 -> {
            showLoading();
            try {
                showLoading();

                // prepare tkey parameters
                verifierId = activity.userInfo.getVerifierId();
                verifier = activity.userInfo.getVerifier();

                List<SessionToken> sessionTokenData = activity.sessionData.getSessionTokenData();
                signatureString = new ArrayList<>();
                for (SessionToken item : sessionTokenData) {
                    if (item != null) {
                        LinkedHashMap<String, Object> msg = new LinkedHashMap<>();
                        msg.put("data", item.getToken());
                        msg.put("sig", item.getSignature());
                        String jsonData = gson.toJson(msg);
                        signatureString.add(jsonData);
                    }
                }

                // node details
                FetchNodeDetails nodeManager = new FetchNodeDetails(TorusNetwork.SAPPHIRE_DEVNET);
                CompletableFuture<NodeDetails> nodeDetailResult = nodeManager.getNodeDetails(verifier, verifierId);
                nodeDetail = nodeDetailResult.get();

                // Torus Utils
                TorusCtorOptions torusOptions = new TorusCtorOptions("Custom");
                torusOptions.setNetwork(TorusNetwork.SAPPHIRE_DEVNET.toString());
                torusOptions.setClientId("BG4pe3aBso5SjVbpotFQGnXVHgxhgOxnqnNBKyjfEJ3izFvIVWUaMIzoCrAfYag8O6t6a6AOvdLcS4JR2sQMjR4");
                TorusUtils torusUtils = new TorusUtils(torusOptions);
                String[] tssEndpoint = nodeDetail.getTorusNodeTSSEndpoints();
                RssComm rss_comm = new RssComm();

                activity.tkeyStorage = new StorageLayer(false, "https://metadata.tor.us", 2);
                activity.tkeyProvider = new ServiceProvider(false, activity.postboxKey,true, verifier, verifierId, nodeDetail);
                activity.tKey = new ThresholdKey(null, null, activity.tkeyStorage, activity.tkeyProvider, null, null, true, false, rss_comm);

                activity.tKey.initialize(activity.postboxKey, null, false, false, false, false, null, 0, null, result -> {
                    if (result instanceof Result.Error) {
                        throw new RuntimeException("Could not initialize tkey");
                    }
                    KeyDetails keyDetails = null;
                    String metadataPublicKey = null;

                    try {
                        keyDetails = activity.tKey.getKeyDetails();
                        metadataPublicKey = keyDetails.getPublicKeyPoint().getPublicKey(KeyPoint.PublicKeyEncoding.EllipticCompress);
                    } catch (RuntimeError e) {
                        throw new RuntimeException(e);
                    }


                    // existing or new user check
                    try {
                        if(keyDetails.getRequiredShares() > 0) {
                            // existing user
                            ArrayList<String> allTags = TSSModule.getAllTSSTags(activity.tKey);
                            String tag = "default"; // allTags[0]
                            String fetchId = metadataPublicKey + ":" + tag + ":0";

                            // fetch key from keystore and assign it to factorKey
                            String factorKey;
                            String retrievedKey = getStringFromSharedPreferences();

                            if (retrievedKey != null) {
                                factorKey = retrievedKey;
                            } else {
                                factorKey = "";
                                throw new RuntimeException("factor key not found in storage");
                            }

                            // input factor key from key store
                            activity.tKey.inputFactorKey(factorKey, inputFactorResult -> {
                                if (inputFactorResult instanceof Result.Error) {
                                    throw new RuntimeException("Could not inputFactorKey for tkey");
                                }
                                PrivateKey pk = new PrivateKey(factorKey);
                                try {
                                    String deviceFactorPub = pk.toPublic(KeyPoint.PublicKeyEncoding.FullAddress);
                                } catch (RuntimeError e) {
                                    throw new RuntimeException(e);
                                }

                                // reconstruct and getTssPubKey
                                activity.tKey.reconstruct(_reconstructResult -> {
                                    if (_reconstructResult instanceof Result.Error) {
                                        throw new RuntimeException("Could not reconstruct tkey");
                                    }
                                    try {
                                        KeyDetails keyDetails2 = activity.tKey.getKeyDetails();
                                    } catch (RuntimeError e) {
                                        throw new RuntimeException(e);
                                    }

                                    TSSModule.getTSSPubKey(activity.tKey, tag, tssPubResult -> {
                                        if (tssPubResult instanceof Result.Error) {
                                            throw new RuntimeException("Could not getTSSPubKey tkey");
                                        }
                                        pubKey.set(((Result.Success<String>) tssPubResult).data);

                                        try {
                                            KeyPoint keyPoint = new KeyPoint(pubKey.get());
                                            fullTssPubKey = keyPoint.getPublicKey(KeyPoint.PublicKeyEncoding.FullAddress);
                                            evmAddress = TssClientHelper.generateAddressFromPubKey(new BigInteger(keyPoint.getX(), 16), new BigInteger(keyPoint.getY(), 16));
                                        } catch (RuntimeError e) {
                                            throw new RuntimeException(e);
                                        }
                                        try {
                                            HashMap<String, ArrayList<String>> defaultTssShareDescription = activity.tKey.getShareDescriptions();
                                        } catch (RuntimeError | JSONException e) {
                                            throw new RuntimeException(e);
                                        }
                                    });

                                    tssNonce = TSSModule.getTSSNonce(activity.tKey, tag, false);

                                    TSSModule.getTSSShare(activity.tKey, tag, factorKey, 0, getTSSShareResult -> {
                                        if (getTSSShareResult instanceof Result.Error) {
                                            System.out.println("could not get tss share");
                                            throw new RuntimeException("could not get tss share");
                                        }
                                        tssShareResponse = ((Result.Success<Pair<String, String>>) getTSSShareResult).data;
                                        tssShare = tssShareResponse.second;
                                        tssIndex = tssShareResponse.first;
                                    });
                                });
                            });
                            userHasCreatedTkey();
                            hideLoading();
                            binding.resultView.append("Log: \n");
                            binding.resultView.append("Tkey Creaetion Successfull" + "\n");
                        } else {
                            // new user
                            // check if reconstruction is working before creating tagged share
                            try {

                                int requiredShares = keyDetails.getRequiredShares();
                                activity.tKey.reconstruct(reconResultInit -> {
                                    if (reconResultInit instanceof Result.Error) {
                                        String errorMsg = "Failed to reconstruct key" + requiredShares  + " more share(s) required. If you have security question share, we suggest you to enter security question PW to recover your account";
                                        throw new RuntimeException(errorMsg);
                                    }

                                    // create tagged tss share
                                    PrivateKey factorKey = null;
                                    String factorPub = null;
                                    try {
                                        factorKey = PrivateKey.generate();
                                        factorPub = factorKey.toPublic(KeyPoint.PublicKeyEncoding.FullAddress);
                                    } catch (RuntimeError e) {
                                        throw new RuntimeException(e);
                                    }
                                    String defaultTag = "default";

                                    //                    re("factorPub", factorPub);
                                    PrivateKey finalFactorKey = factorKey;
                                    try {
                                        PrivateKey finalFactorKey1 = factorKey;
                                        TSSModule.createTaggedTSSTagShare(activity.tKey, defaultTag, null, factorPub, 2, nodeDetail, torusUtils, createTaggedResult -> {
                                            if (createTaggedResult instanceof Result.Error) {
                                                throw new RuntimeException("Could not createTaggedTSSTagShare tkey");
                                            }
                                            AtomicReference<String> pubKeyNew = new AtomicReference<>("");
                                            TSSModule.getTSSPubKey(activity.tKey, defaultTag, getTSSPubKeyResult -> {
                                                if (getTSSPubKeyResult instanceof Result.Error) {
                                                    throw new RuntimeException("Could not getTSSPubKey tkey");
                                                }
                                                pubKeyNew.set(((Result.Success<String>) getTSSPubKeyResult).data);

                                                // backup share with input factor key
                                                ArrayList<String> shareIndexes = null;
                                                JSONObject description = new JSONObject();

                                                try {
                                                    shareIndexes = activity.tKey.getShareIndexes();

                                                    shareIndexes.removeIf(index -> index.equals("1"));
                                                    TSSModule.backupShareWithFactorKey(activity.tKey, shareIndexes.get(0), finalFactorKey.hex);

                                                    // add share description
                                                        description.put("module", "Device Factor key");
                                                        description.put("tssTag", defaultTag);
                                                        description.put("tssShareIndex", 2);
                                                        description.put("dateAdded", System.currentTimeMillis()/1000);
                                                } catch (JSONException | RuntimeError e) {
                                                    throw new RuntimeException(e);
                                                }
                                                activity.tKey.addShareDescription(shareIndexes.get(0), description.toString(), true, addShareResult -> {
                                                    if (addShareResult instanceof Result.Error) {
                                                        throw new RuntimeException("Could not add share description for tkey");
                                                    }

                                                    saveStringToSharedPreferences(finalFactorKey.hex);

                                                    // reconstruction
                                                    activity.tKey.reconstruct(reconstructResult -> {
                                                        if (reconstructResult instanceof Result.Error) {
                                                            String errorMsg = "Failed to reconstruct key" + requiredShares  + " more share(s) required. If you have security question share, we suggest you to enter security question PW to recover your account";
                                                            throw new RuntimeException(errorMsg);
                                                        }
                                                        try {
                                                            HashMap<String, ArrayList<String>> shareDescriptions = activity.tKey.getShareDescriptions();
                                                        } catch (RuntimeError | JSONException e) {
                                                            throw new RuntimeException(e);
                                                        }

                                                        tssNonce = TSSModule.getTSSNonce(activity.tKey, defaultTag, false);

                                                        TSSModule.getTSSShare(activity.transferKey, defaultTag, finalFactorKey1.hex, 0, _result -> {
                                                            if (_result instanceof Result.Error) {
                                                                System.out.println("Could not create tagged tss shares for tkey");
                                                            }
                                                            tssShareResponse = ((Result.Success<Pair<String, String>>) _result).data;
                                                            tssShare = tssShareResponse.second;
                                                            tssIndex = tssShareResponse.first;
                                                        });
                                                        // disable button
                                                        userHasCreatedTkey();
                                                        hideLoading();
                                                        binding.resultView.append("Log: \n");
                                                        binding.resultView.append("Tkey Creaetion Successfull" + "\n");
                                                    });
                                                });
                                            });
                                        });
                                    } catch (Exception | RuntimeError e) {
                                        throw new RuntimeException(e);
                                    }
                                });

                            } catch (Exception | RuntimeError e) {
                                TssClientHelper.showAlert(activity, "Error: " + e.getMessage());
                                hideLoading();
                                renderError(e);
                            }
                        }
                    } catch (RuntimeError | JSONException e) {
                        TssClientHelper.showAlert(activity, "Error: " + e.getMessage());
                        throw new RuntimeException(e);
                    }

                });
            } catch (Exception | RuntimeError e) {
                TssClientHelper.showAlert(activity, "Error: " + e.getMessage());
                hideLoading();
                renderError(e);
            }
        });

//        binding.reconstructThresholdKey.setOnClickListener(view1 -> activity.tKey.reconstruct(result -> {
//            showLoading();
//            if (result instanceof Result.Error) {
//                renderError(((Result.Error<KeyReconstructionDetails>) result).exception);
//                hideLoading();
//            } else if (result instanceof Result.Success) {
//                requireActivity().runOnUiThread(() -> {
//                    try {
//                        KeyReconstructionDetails details = ((Result.Success<KeyReconstructionDetails>) result).data;
//                        binding.generateNewShare.setEnabled(true);
//                        Snackbar snackbar = Snackbar.make(view1, details.getKey(), Snackbar.LENGTH_LONG);
//                        snackbar.show();
//                    } catch (RuntimeError e) {
//                        renderError(e);
//                    } finally {
//                        hideLoading();
//                    }
//                });
//            }
//        }));

//        binding.generateNewShare.setOnClickListener(view1 -> {
//            showLoading();
//            try {
//                activity.tKey.generateNewShare(result -> {
//                    if (result instanceof Result.Error) {
//                        requireActivity().runOnUiThread(() -> {
//                            Exception e = ((Result.Error<GenerateShareStoreResult>) result).exception;
//                            Snackbar snackbar = Snackbar.make(view1, "A problem occurred: " + e.toString(), Snackbar.LENGTH_LONG);
//                            snackbar.show();
//                            hideLoading();
//                        });
//                    } else if (result instanceof Result.Success) {
//                        requireActivity().runOnUiThread(() -> {
//                            try {
//                                GenerateShareStoreResult share = ((Result.Success<GenerateShareStoreResult>) result).data;
//                                String shareIndexCreated = share.getIndex();
//                                activity.sharedpreferences.edit().putString(SHARE_INDEX_GENERATED_ALIAS, shareIndexCreated).apply();
//                                binding.deleteShare.setEnabled(true);
//                                Snackbar snackbar = Snackbar.make(view1, share.getIndex() + "created", Snackbar.LENGTH_LONG);
//                                snackbar.show();
//
//                                // update result view
//                                activity.tKey.reconstruct((reconstructionDetailsResult) -> {
//                                    try {
//                                        if (reconstructionDetailsResult instanceof Result.Error) {
//                                            hideLoading();
//                                            renderError(((Result.Error<KeyReconstructionDetails>) reconstructionDetailsResult).exception);
//                                        } else if (reconstructionDetailsResult instanceof Result.Success) {
//                                            KeyDetails details = activity.tKey.getKeyDetails();
//                                            renderTKeyDetails(((Result.Success<KeyReconstructionDetails>) reconstructionDetailsResult).data, details);
//                                            hideLoading();
//                                        }
//
//                                    } catch (RuntimeError e) {
//                                        hideLoading();
//                                        renderError(e);
//                                    }
//
//                                });
//                            } catch (RuntimeError e) {
//                                renderError(e);
//                                hideLoading();
//                            }
//                        });
//                    }
//                });
//            } catch (Exception e) {
//                renderError(e);
//            }
//        });
//
//        binding.deleteShare.setOnClickListener(view1 -> {
//            showLoading();
//            String shareIndexCreated = activity.sharedpreferences.getString(SHARE_INDEX_GENERATED_ALIAS, null);
//            if (shareIndexCreated != null) {
//                activity.tKey.deleteShare(shareIndexCreated, result -> {
//                    if (result instanceof Result.Error) {
//                        requireActivity().runOnUiThread(() -> {
//                            Exception e = ((Result.Error<Void>) result).exception;
//                            renderError(e);
//                            hideLoading();
//                        });
//                    } else if (result instanceof Result.Success) {
//                        requireActivity().runOnUiThread(() -> {
//                            binding.resetAccount.setEnabled(true);
//                            Snackbar snackbar;
//                            snackbar = Snackbar.make(view1, shareIndexCreated + " deleted", Snackbar.LENGTH_LONG);
//                            snackbar.show();
//                        });
//                        // update result view
//                        activity.tKey.reconstruct((reconstructionDetailsResult) -> {
//                            try {
//                                if (reconstructionDetailsResult instanceof Result.Error) {
//                                    hideLoading();
//                                    renderError(((Result.Error<KeyReconstructionDetails>) reconstructionDetailsResult).exception);
//                                } else if (reconstructionDetailsResult instanceof Result.Success) {
//                                    KeyDetails details = activity.tKey.getKeyDetails();
//                                    requireActivity().runOnUiThread(() -> {
//                                        renderTKeyDetails(((Result.Success<KeyReconstructionDetails>) reconstructionDetailsResult).data, details);
//                                        hideLoading();
//                                        binding.deleteShare.setEnabled(false);
//                                    });
//                                }
//                            } catch (RuntimeError e) {
//                                renderError(e);
//                                hideLoading();
//                            }
//
//                        });
//
//                    }
//                });
//            } else {
//                requireActivity().runOnUiThread(() -> {
//                    Snackbar snackbar;
//                    snackbar = Snackbar.make(view1, "No share index found", Snackbar.LENGTH_LONG);
//                    snackbar.show();
//                });
//            }
//        });
//
//        binding.addPassword.setOnClickListener(view1 -> {
//            showLoading();
//            try {
//                String question = "what's your password?";
//                String answer = generateRandomPassword(12);
//                SecurityQuestionModule.generateNewShare(activity.tKey, question, answer, result -> {
//                    if (result instanceof Result.Error) {
//                        requireActivity().runOnUiThread(() -> {
//                            Exception e = ((Result.Error<GenerateShareStoreResult>) result).exception;
//                            Snackbar snackbar = Snackbar.make(view1, "A problem occurred: " + e.toString(), Snackbar.LENGTH_LONG);
//                            snackbar.show();
//                            hideLoading();
//                        });
//                    } else if (result instanceof Result.Success) {
//                        requireActivity().runOnUiThread(() -> {
//                            try {
//                                GenerateShareStoreResult share = ((Result.Success<GenerateShareStoreResult>) result).data;
//                                String setAnswer = SecurityQuestionModule.getAnswer(activity.tKey);
//                                binding.addPassword.setEnabled(false);
//                                binding.changePassword.setEnabled(true);
//                                Snackbar snackbar = Snackbar.make(view1, "Added password " + setAnswer + " for share index" + share.getIndex(), Snackbar.LENGTH_LONG);
//                                snackbar.show();
//                                activity.sharedpreferences.edit().putString(ADD_PASSWORD_SET_ALIAS, "SET").apply();
//                                // update result view
//                                activity.tKey.reconstruct((reconstructionDetailsResult) -> {
//                                    try {
//                                        if (reconstructionDetailsResult instanceof Result.Error) {
//                                            hideLoading();
//                                            renderError(((Result.Error<KeyReconstructionDetails>) reconstructionDetailsResult).exception);
//                                        } else if (reconstructionDetailsResult instanceof Result.Success) {
//                                            KeyDetails details = activity.tKey.getKeyDetails();
//                                            renderTKeyDetails(((Result.Success<KeyReconstructionDetails>) reconstructionDetailsResult).data, details);
//                                            hideLoading();
//                                        }
//                                    } catch (RuntimeError e) {
//                                        hideLoading();
//                                        renderError(e);
//                                    }
//
//                                });
//                            } catch (RuntimeError e) {
//                                Snackbar snackbar = Snackbar.make(view1, "A problem occurred: " + e, Snackbar.LENGTH_LONG);
//                                snackbar.show();
//                                hideLoading();
//                            }
//                        });
//                    }
//                });
//            } catch (Exception e) {
//                Snackbar snackbar = Snackbar.make(view1, "A problem occurred: " + e, Snackbar.LENGTH_LONG);
//                snackbar.show();
//                hideLoading();
//            }
//        });
//
//        binding.changePassword.setOnClickListener(view1 -> {
//            AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
//            builder.setTitle("Enter Password");
//
//            // Create an EditText for password input
//            final EditText passwordEditText = new EditText(getContext());
//            passwordEditText.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
//            builder.setView(passwordEditText);
//
//            builder.setPositiveButton("OK", (dialog, which) -> {
//                String password = passwordEditText.getText().toString();
//                // Handle the entered password
//                showLoading();
//                try {
//                    String question = "what's your password?";
//                    SecurityQuestionModule.changeSecurityQuestionAndAnswer(activity.tKey, question, password, result -> {
//                        if (result instanceof Result.Error) {
//                            requireActivity().runOnUiThread(() -> {
//                                renderError(((Result.Error<Boolean>) result).exception);
//                                hideLoading();
//                            });
//                        } else if (result instanceof Result.Success) {
//                            requireActivity().runOnUiThread(() -> {
//                                try {
//                                    Boolean changed = ((Result.Success<Boolean>) result).data;
//                                    if (changed) {
//                                        String setAnswer = SecurityQuestionModule.getAnswer(activity.tKey);
//                                        binding.changePassword.setEnabled(false);
//                                        Snackbar snackbar = Snackbar.make(view1, "Password changed to" + setAnswer, Snackbar.LENGTH_LONG);
//                                        snackbar.show();
//                                        hideLoading();
//                                    } else {
//                                        Snackbar snackbar = Snackbar.make(view1, "Password failed to be changed", Snackbar.LENGTH_LONG);
//                                        snackbar.show();
//                                        hideLoading();
//                                    }
//                                } catch (RuntimeError e) {
//                                    Snackbar snackbar = Snackbar.make(view1, "A problem occurred: " + e, Snackbar.LENGTH_LONG);
//                                    snackbar.show();
//                                    hideLoading();
//                                }
//                            });
//                        }
//                    });
//                } catch (Exception e) {
//                    renderError(e);
//                    hideLoading();
//                }
//            });
//
//            builder.setNegativeButton("Cancel", (dialog, which) -> dialog.cancel());
//            AlertDialog dialog = builder.create();
//            dialog.show();
//        });
//
//        binding.showPassword.setOnClickListener(view1 -> {
//            try {
//                String answer = SecurityQuestionModule.getAnswer(activity.tKey);
//                Snackbar snackbar = Snackbar.make(view1, "Password currently is " + answer, Snackbar.LENGTH_LONG);
//                snackbar.show();
//            } catch (RuntimeError e) {
//                renderError(e);
//
//            }
//        });
//
//        binding.setSeedPhrase.setOnClickListener(view1 -> {
//            showLoading();
//            String phrase = "seed sock milk update focus rotate barely fade car face mechanic mercy";
//            SeedPhraseModule.setSeedPhrase(activity.tKey, "HD Key Tree", phrase, 0, result -> {
//                if (result instanceof Result.Error) {
//                    requireActivity().runOnUiThread(() -> {
//                        Exception e = ((Result.Error<Boolean>) result).exception;
//                        Snackbar snackbar = Snackbar.make(view1, "A problem occurred: " + e.toString(), Snackbar.LENGTH_LONG);
//                        snackbar.show();
//                        hideLoading();
//                    });
//                } else if (result instanceof Result.Success) {
//                    Boolean set = ((Result.Success<Boolean>) result).data;
//                    if (set) {
//                        activity.sharedpreferences.edit().putString(SEED_PHRASE_ALIAS, phrase).apply();
//                        requireActivity().runOnUiThread(() -> {
//                            Snackbar snackbar;
//                            snackbar = Snackbar.make(view1, "Seed phrase set", Snackbar.LENGTH_LONG);
//                            snackbar.show();
//                        });
//                        activity.sharedpreferences.edit().putString(SEED_PHRASE_SET_ALIAS, "SET").apply();
//                        // update result view
//                        activity.tKey.reconstruct((reconstructionDetailsResult) -> {
//                            try {
//                                if (reconstructionDetailsResult instanceof Result.Error) {
//                                    renderError(((Result.Error<KeyReconstructionDetails>) reconstructionDetailsResult).exception);
//                                    hideLoading();
//                                } else if (reconstructionDetailsResult instanceof Result.Success) {
//                                    KeyDetails details = activity.tKey.getKeyDetails();
//                                    requireActivity().runOnUiThread(() -> {
//                                        binding.setSeedPhrase.setEnabled(false);
//                                        binding.changeSeedPhrase.setEnabled(true);
//                                        binding.deleteSeedPhrase.setEnabled(true);
//                                    });
//                                    renderTKeyDetails(((Result.Success<KeyReconstructionDetails>) reconstructionDetailsResult).data, details);
//                                    hideLoading();
//                                }
//
//                            } catch (RuntimeError e) {
//                                hideLoading();
//                                renderError(e);
//                            }
//
//                        });
//                    } else {
//                        requireActivity().runOnUiThread(() -> {
//                            Snackbar snackbar;
//                            snackbar = Snackbar.make(view1, "Failed to set seed phrase", Snackbar.LENGTH_LONG);
//                            snackbar.show();
//                        });
//                    }
//                }
//            });
//        });
//
//        binding.changeSeedPhrase.setOnClickListener(view1 -> {
//            showLoading();
//            String oldPhrase = "seed sock milk update focus rotate barely fade car face mechanic mercy";
//            String newPhrase = "object brass success calm lizard science syrup planet exercise parade honey impulse";
//            SeedPhraseModule.changePhrase(activity.tKey, oldPhrase, newPhrase, result -> {
//                if (result instanceof Result.Error) {
//                    requireActivity().runOnUiThread(() -> {
//                        Exception e = ((Result.Error<Boolean>) result).exception;
//                        renderError(e);
//                        hideLoading();
//                    });
//                } else if (result instanceof Result.Success) {
//                    Boolean changed = ((Result.Success<Boolean>) result).data;
//                    if (changed) {
//                        activity.sharedpreferences.edit().putString(SEED_PHRASE_ALIAS, newPhrase).apply();
//                        requireActivity().runOnUiThread(() -> {
//                            Snackbar snackbar = Snackbar.make(view1, "Seed phrase changed", Snackbar.LENGTH_LONG);
//                            snackbar.show();
//                            binding.changeSeedPhrase.setEnabled(false);
//                            binding.deleteSeedPhrase.setEnabled(true);
//                        });
//                        hideLoading();
//                    } else {
//                        requireActivity().runOnUiThread(() -> {
//                            Snackbar snackbar = Snackbar.make(view1, "Failed to change seed phrase", Snackbar.LENGTH_LONG);
//                            snackbar.show();
//                        });
//                        hideLoading();
//                    }
//                }
//            });
//        });
//
//        binding.getSeedPhrase.setOnClickListener(view1 -> {
//            try {
//                String phrases = SeedPhraseModule.getPhrases(activity.tKey);
//                Snackbar snackbar = Snackbar.make(view1, phrases, Snackbar.LENGTH_LONG);
//                snackbar.show();
//            } catch (RuntimeError e) {
//                renderError(e);
//            }
//        });
//
        binding.resetAccount.setOnClickListener(view1 -> {
            try {
                // delete locally stored share
                StorageLayer temp_sl = new StorageLayer(false, "https://metadata.tor.us", 2);
                ServiceProvider temp_sp = new ServiceProvider(false, activity.postboxKey,true, null, null, null);
                ThresholdKey temp_key = new ThresholdKey(null, null, temp_sl, temp_sp, null, null, true, false, null);

                activity.sharedpreferences.edit().clear().apply();

                temp_key.storage_layer_set_metadata(activity.postboxKey, "{ \"message\": \"KEY_NOT_FOUND\" }", result -> {
                    if (result instanceof Result.Error) {
                        activity.runOnUiThread(() -> {
                            Exception e = ((Result.Error<Void>) result).exception;
                            renderError(e);
                        });
                    } else if (result instanceof Result.Success) {
                        activity.runOnUiThread(() -> {
                            activity.resetState();
                            userHasNotLoggedInWithGoogle();
                            binding.resultView.setText("");
                            Snackbar snackbar = Snackbar.make(view1, "Account reset successful", Snackbar.LENGTH_LONG);
                            snackbar.show();
                        });

                    }
                });

                activity.postboxKey = null;

            } catch (RuntimeError | JSONException e) {
                Snackbar snackbar = Snackbar.make(view1, "A problem occurred: " + e.getMessage(), Snackbar.LENGTH_LONG);
                snackbar.show();
            }
        });
//
//        binding.deleteSeedPhrase.setOnClickListener(view1 -> {
//            showLoading();
//            try {
//                String newPhrase = "object brass success calm lizard science syrup planet exercise parade honey impulse";
//                String phrase = activity.sharedpreferences.getString(SEED_PHRASE_ALIAS, newPhrase);
//                SeedPhraseModule.deletePhrase(activity.tKey, phrase, result -> {
//                    if (result instanceof Result.Error) {
//                        requireActivity().runOnUiThread(() -> {
//                            Exception e = ((Result.Error<Boolean>) result).exception;
//                            renderError(e);
//                        });
//                    } else if (result instanceof Result.Success) {
//                        Boolean deleted = ((Result.Success<Boolean>) result).data;
//                        if (deleted) {
//                            // update result view
//                            activity.tKey.reconstruct((reconstructionDetailsResult) -> {
//                                try {
//                                    if (reconstructionDetailsResult instanceof Result.Error) {
//                                        hideLoading();
//                                        renderError(((Result.Error<KeyReconstructionDetails>) reconstructionDetailsResult).exception);
//                                    } else if (reconstructionDetailsResult instanceof Result.Success) {
//                                        KeyDetails details = activity.tKey.getKeyDetails();
//                                        requireActivity().runOnUiThread(() -> {
//                                            binding.deleteSeedPhrase.setEnabled(false);
//                                            binding.setSeedPhrase.setEnabled(true);
//                                            binding.changeSeedPhrase.setEnabled(false);
//                                            binding.getSeedPhrase.setEnabled(false);
//                                        });
//                                        renderTKeyDetails(((Result.Success<KeyReconstructionDetails>) reconstructionDetailsResult).data, details);
//                                        hideLoading();
//                                    }
//
//                                } catch (RuntimeError e) {
//                                    hideLoading();
//                                    renderError(e);
//                                }
//
//                            });
//                            requireActivity().runOnUiThread(() -> {
//                                Snackbar snackbar = Snackbar.make(view1, "Phrase Deleted", Snackbar.LENGTH_LONG);
//                                snackbar.show();
//                                hideLoading();
//                            });
//                        } else {
//                            requireActivity().runOnUiThread(() -> {
//                                Snackbar snackbar = Snackbar.make(view1, "Phrase failed ot be deleted", Snackbar.LENGTH_LONG);
//                                snackbar.show();
//                                hideLoading();
//                            });
//                        }
//                    }
//                });
//            } catch (Exception e) {
//                renderError(e);
//            }
//        });
//
//        binding.exportShare.setOnClickListener(view1 -> activity.tKey.generateNewShare(result -> {
//            showLoading();
//            if (result instanceof Result.Error) {
//                requireActivity().runOnUiThread(() -> {
//                    Exception e = ((Result.Error<GenerateShareStoreResult>) result).exception;
//                    renderError(e);
//                    hideLoading();
//                });
//            } else if (result instanceof Result.Success) {
//                requireActivity().runOnUiThread(() -> {
//                    try {
//                        GenerateShareStoreResult shareStoreResult = ((Result.Success<GenerateShareStoreResult>) result).data;
//                        String index = shareStoreResult.getIndex();
//                        String share = activity.tKey.outputShare(index);
//                        String serialized = ShareSerializationModule.serializeShare(activity.tKey, share);
//                        Snackbar snackbar = Snackbar.make(view1, "Serialization result: " + serialized, Snackbar.LENGTH_LONG);
//                        snackbar.show();
//                        hideLoading();
//                    } catch (RuntimeError e) {
//                        renderError(e);
//                        hideLoading();
//                    }
//                });
//            }
//        }));
//
//        binding.setPrivateKey.setOnClickListener(view1 -> {
//            showLoading();
//            try {
//                PrivateKey newKey = PrivateKey.generate();
//                PrivateKeysModule.setPrivateKey(activity.tKey, newKey.hex, "secp256k1n", result -> {
//                    if (result instanceof Result.Error) {
//                        requireActivity().runOnUiThread(() -> {
//                            Exception e = ((Result.Error<Boolean>) result).exception;
//                            renderError(e);
//                            hideLoading();
//                        });
//                    } else if (result instanceof Result.Success) {
//                        Boolean set = ((Result.Success<Boolean>) result).data;
//                        Snackbar snackbar = Snackbar.make(view1, "Set private key result: " + set, Snackbar.LENGTH_LONG);
//                        snackbar.show();
//                        hideLoading();
//                    }
//                });
//            } catch (RuntimeError e) {
//                renderError(e);
//                hideLoading();
//            }
//        });
//
//        binding.getPrivateKey.setOnClickListener(view1 -> {
//            showLoading();
//            try {
//                String key = PrivateKeysModule.getPrivateKeys(activity.tKey);
//                Snackbar snackbar = Snackbar.make(view1, key, Snackbar.LENGTH_LONG);
//                snackbar.show();
//                hideLoading();
//            } catch (RuntimeError e) {
//                renderError(e);
//                hideLoading();
//            }
//        });

//        binding.getAccounts.setOnClickListener(view1 -> {
//            showLoading();
//            try {
//                ArrayList<String> accounts = PrivateKeysModule.getPrivateKeyAccounts(activity.tKey);
//                Snackbar snackbar = Snackbar.make(view1, accounts.toString(), Snackbar.LENGTH_LONG);
//                snackbar.show();
//                hideLoading();
//            } catch (RuntimeError | JSONException e) {
//                renderError(e);
//                hideLoading();
//            }
//        });

//        binding.getKeyDetails.setOnClickListener(view1 -> {
//            try {
//                KeyDetails keyDetails = activity.tKey.getKeyDetails();
//                String snackbarContent = "There are " + (keyDetails.getTotalShares()) + " available shares. " + (keyDetails.getRequiredShares()) + " are required to reconstruct the private key";
//                Snackbar snackbar = Snackbar.make(view1, snackbarContent, Snackbar.LENGTH_LONG);
//                snackbar.show();
//            } catch (RuntimeError e) {
//                renderError(e);
//            }
//        });

        binding.tssSignMessage.setOnClickListener(_view -> {
            showLoading();
            sign();
        });

        binding.tssSignTransaction.setOnClickListener(_view -> {
            try {
                showLoading();

                String url = "https://rpc.ankr.com/eth_goerli";
                Web3j web3j = Web3j.build(new HttpService(url));
                double amount = 0.001;
                String fromAdress = evmAddress;
                String toAddress = evmAddress;
                AtomicReference<RawTransaction> rawTransaction = new AtomicReference<>();
                new Thread(() -> {
                    try {
                        EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
                                fromAdress,
                                DefaultBlockParameterName.LATEST
                        ).send();
                        BigInteger nonce = ethGetTransactionCount.getTransactionCount();
                        BigInteger value = Convert.toWei(Double.toString(amount), Convert.Unit.ETHER).toBigInteger();
                        BigInteger gasLimit = BigInteger.valueOf(21000);
                        EthGasPrice gasPriceResponse = web3j.ethGasPrice().send();
                        BigInteger gasPrice = gasPriceResponse.getGasPrice();
                        EthChainId chainIdResponse = web3j.ethChainId().sendAsync().get();
                        BigInteger chainId = chainIdResponse.getChainId();

                        rawTransaction.set(RawTransaction.createTransaction(
                                chainId.longValue(),
                                nonce,
                                gasLimit,
                                toAddress,
                                value,
                                "",
                                gasPrice,
                                gasPrice
                        ));

                        TSSClient client;
                        Map<String, String> coeffs;
                        Pair<TSSClient, Map<String, String>> clientCoeffsPair;
                        try {
                            clientCoeffsPair = TssClientHelper.helperTssClient("default", tssNonce, fullTssPubKey, tssShare, tssIndex,
                                    Arrays.asList(nodeDetail.getTorusIndexes()), factor_key, this.verifier, verifierId, Arrays.asList(nodeDetail.getTorusNodeTSSEndpoints()));
                            client = clientCoeffsPair.first;
                            coeffs = clientCoeffsPair.second;

                            // Wait for sockets to be connected
                            boolean connected;
                            try {
                                connected = client.checkConnected();
                            } catch (Exception e) {
                                hideLoading();
                                throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
                            }

                            if (connected) {
                                Precompute precompute;
                                try {
                                    precompute = client.precompute(coeffs, signatureString);
                                } catch (Exception e) {
                                    hideLoading();
                                    throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
                                }

                                boolean ready;
                                try {
                                    ready = client.isReady();
                                } catch (Exception e) {
                                    hideLoading();
                                    throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
                                }

                                if (ready) {
                                    //to check
                                    RawTransaction raw = rawTransaction.get();
                                    if (raw == null) {
                                        throw new EthereumSignerError(EthereumSignerError.ErrorType.EMPTY_RAW_TRANSACTION);
                                    }

                                    byte[] encodedTransaction = TransactionEncoder.encode(rawTransaction.get());
                                    String encodedTransactionString = Base64.encodeToString(Hash.sha3(encodedTransaction), Base64.NO_WRAP);

                                    Triple<BigInteger, BigInteger, Byte> signatureResult;
                                    try {
                                        signatureResult = client.sign(encodedTransactionString, true, "", precompute, signatureString);
                                    } catch (TSSClientError e) {
                                        hideLoading();
                                        throw new RuntimeException(e);
                                    }
                                    try {
                                        client.cleanup(signatureString.toArray(new String[0]));
                                    } catch (TSSClientError e) {
                                        hideLoading();
                                        throw new RuntimeException(e);
                                    }

                                    //getFirst() : s, getSecond(): r, getThird(): v
                                    String signature = TSSHelpers.hexSignature(signatureResult.getFirst(),
                                            signatureResult.getSecond(), signatureResult.getThird());
                                    try {
                                        Sign.SignatureData signatureData = new Sign.SignatureData((byte) (signatureResult.getThird() + 27),
                                                signatureResult.getSecond().toByteArray(),
                                                signatureResult.getFirst().toByteArray());
                                        byte[] signedMsg = TransactionEncoder.encode(rawTransaction.get(), signatureData);

                                        String finalSig = Numeric.toHexString(signedMsg);
                                        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(finalSig).send();
                                        hideLoading();
                                        if (ethSendTransaction.getError() != null) {
                                            activity.runOnUiThread(() -> TssClientHelper.showAlert(activity, "Error: " + ethSendTransaction.getError().getMessage()));
                                        } else {
                                            activity.runOnUiThread(() -> TssClientHelper.showAlert(activity, "TransactionHash: " + ethSendTransaction.getTransactionHash()));
                                        }
                                    } catch (IOException e) {
                                        hideLoading();
                                        throw new RuntimeException(e);
                                    }
                                } else {
                                    hideLoading();
                                    activity.runOnUiThread(() -> Toast.makeText(activity, "Client is not ready, please try again", Toast.LENGTH_LONG).show());
                                }
                            } else {
                                hideLoading();
                                activity.runOnUiThread(() -> Toast.makeText(activity, "Client is not connected, please try again", Toast.LENGTH_LONG).show());
                            }
                        } catch (Exception | RuntimeError e) {
                            hideLoading();
                            throw new RuntimeException(e);
                        }
                    } catch (IOException | ExecutionException | InterruptedException e) {
                        hideLoading();
                        throw new RuntimeException(e);
                    }
                }).start();
            } catch (Exception e) {
                hideLoading();
                throw new RuntimeException(e);
            }
        });
    }

    private void sign() {
        TSSClient client;
        Map<String, String> coeffs;
        Pair<TSSClient, Map<String, String>> clientCoeffsPair;
        try {
            clientCoeffsPair = TssClientHelper.helperTssClient("default", tssNonce, fullTssPubKey, tssShare, tssIndex,
                    Arrays.asList(nodeDetail.getTorusIndexes()), factor_key, this.verifier, verifierId, Arrays.asList(nodeDetail.getTorusNodeTSSEndpoints()));
            client = clientCoeffsPair.first;
            coeffs = clientCoeffsPair.second;

            // Wait for sockets to be connected
            boolean connected;
            try {
                connected = client.checkConnected();
            } catch (Exception e) {
                throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
            }

            if(connected) {
                new Thread(() -> {
                    Precompute precompute;
                    try {
                        precompute = client.precompute(coeffs, signatureString);
                    } catch (Exception e) {
                        e.printStackTrace();
                        throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
                    }

                    boolean ready;
                    try {
                        ready = client.isReady();
                    } catch (Exception e) {
                        throw new EthereumSignerError(EthereumSignerError.ErrorType.UNKNOWN_ERROR);
                    }

                    if (ready) {
                        String msg = "hello world";
                        String msgHash = TSSHelpers.hashMessage(msg);
                        Triple<BigInteger, BigInteger, Byte> signatureResult;
                        try {
                            signatureResult = client.sign(msgHash, true, msg, precompute, signatureString);
                        } catch (TSSClientError e) {
                            throw new RuntimeException(e);
                        }
                        try {
                            client.cleanup(signatureString.toArray(new String[0]));
                        } catch (TSSClientError e) {
                            throw new RuntimeException(e);
                        }

                        String uncompressedPubKey;
                        try {
                            uncompressedPubKey = new KeyPoint(pubKey.get()).getPublicKey(KeyPoint.PublicKeyEncoding.FullAddress);
                        } catch (RuntimeError e) {
                            throw new RuntimeException(e);
                        }
                        boolean verify = TSSHelpers.verifySignature(msgHash, signatureResult.getFirst(),
                                signatureResult.getSecond(), signatureResult.getThird(), TssClientHelper.convertToBytes(uncompressedPubKey));

                        hideLoading();
                        if (verify) {
                            String signature = "Signature: " + TSSHelpers.hexSignature(signatureResult.getFirst(),
                                    signatureResult.getSecond(), signatureResult.getThird());
                            requireActivity().runOnUiThread(() -> TssClientHelper.showAlert(requireActivity(), signature));
                        } else {
                            requireActivity().runOnUiThread(() -> Toast.makeText(requireActivity(), "Signature could not be verified", Toast.LENGTH_LONG).show());
                        }

                    } else {
                        hideLoading();
                        requireActivity().runOnUiThread(() -> Toast.makeText(requireActivity(), "Client is not ready, please try again", Toast.LENGTH_LONG).show());
                    }
                }).start();
            } else {
                hideLoading();
                requireActivity().runOnUiThread(() -> Toast.makeText(requireActivity(), "Client is not connected, please try again", Toast.LENGTH_LONG).show());
            }
        } catch (Exception | RuntimeError e) {
            hideLoading();
            throw new RuntimeException(e);
        }
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

    private void userHasNotLoggedInWithGoogle() {
        requireActivity().runOnUiThread(() -> {
            binding.googleLogin.setEnabled(true);
            binding.createThresholdKey.setEnabled(false);
//            binding.reconstructThresholdKey.setEnabled(false);
//            binding.generateNewShare.setEnabled(false);
//            binding.deleteShare.setEnabled(false);
//            binding.deleteSeedPhrase.setEnabled(false);
            binding.resetAccount.setEnabled(false);
            binding.tssSignMessage.setEnabled(false);
            binding.tssSignTransaction.setEnabled(false);
//            binding.getKeyDetails.setEnabled(false);
//            binding.addPassword.setEnabled(false);
//            binding.changePassword.setEnabled(false);
//            binding.showPassword.setEnabled(false);
//            binding.setSeedPhrase.setEnabled(false);
//            binding.deleteSeedPhrase.setEnabled(false);
//            binding.exportShare.setEnabled(false);
//            binding.getPrivateKey.setEnabled(false);
//            binding.setPrivateKey.setEnabled(false);
//            binding.changeSeedPhrase.setEnabled(false);
//            binding.getSeedPhrase.setEnabled(false);
//            binding.getAccounts.setEnabled(false);
//            binding.requestStatusCheck.setEnabled(false);
//            binding.cleanupRequests.setEnabled(false);
//            binding.requestNewShare.setEnabled(false);
//            binding.lookForRequests.setEnabled(false);
        });
    }

    private void userHasLoggedInWithGoogle() {
        requireActivity().runOnUiThread(() -> {
            binding.googleLogin.setEnabled(false);
            binding.createThresholdKey.setEnabled(true);
//            binding.reconstructThresholdKey.setEnabled(false);
//            binding.generateNewShare.setEnabled(false);
//            binding.deleteShare.setEnabled(false);
//            binding.deleteSeedPhrase.setEnabled(false);
            binding.resetAccount.setEnabled(true);
            binding.tssSignMessage.setEnabled(false);
            binding.tssSignTransaction.setEnabled(false);
//            binding.getKeyDetails.setEnabled(false);
//            binding.addPassword.setEnabled(false);
//            binding.changePassword.setEnabled(false);
//            binding.showPassword.setEnabled(false);
//            binding.setSeedPhrase.setEnabled(false);
//            binding.deleteSeedPhrase.setEnabled(false);
//            binding.exportShare.setEnabled(false);
//            binding.getPrivateKey.setEnabled(false);
//            binding.setPrivateKey.setEnabled(false);
//            binding.changeSeedPhrase.setEnabled(false);
//            binding.getSeedPhrase.setEnabled(false);
//            binding.getAccounts.setEnabled(false);
        });
    }

    private void userHasCreatedTkey() {
        MainActivity activity = (MainActivity) requireActivity();
        requireActivity().runOnUiThread(() -> {
            binding.googleLogin.setEnabled(false);
            binding.createThresholdKey.setEnabled(false);
//            binding.reconstructThresholdKey.setEnabled(true);
//            binding.generateNewShare.setEnabled(true);
//            binding.deleteShare.setEnabled(activity.sharedpreferences.getString(SHARE_INDEX_GENERATED_ALIAS, null) != null);
//            binding.deleteSeedPhrase.setEnabled(true);
            binding.resetAccount.setEnabled(true);
            binding.tssSignMessage.setEnabled(true);
            binding.tssSignTransaction.setEnabled(true);

//            binding.getKeyDetails.setEnabled(true);
//            binding.addPassword.setEnabled(!activity.sharedpreferences.getString(ADD_PASSWORD_SET_ALIAS, "").equals("SET"));
//            binding.changePassword.setEnabled(false);
//            binding.showPassword.setEnabled(false);
//            binding.setSeedPhrase.setEnabled(!activity.sharedpreferences.getString(SEED_PHRASE_SET_ALIAS, "").equals("SET"));
//            binding.deleteSeedPhrase.setEnabled(true);
//            binding.exportShare.setEnabled(true);
//            binding.getPrivateKey.setEnabled(true);
//            binding.setPrivateKey.setEnabled(true);
//            binding.changeSeedPhrase.setEnabled(true);
//            binding.getSeedPhrase.setEnabled(true);
//            binding.getAccounts.setEnabled(false);
//            binding.requestNewShare.setEnabled(true);
        });
    }

    private void renderTKeyDetails(KeyReconstructionDetails reconstructionDetails, KeyDetails details) {
        requireActivity().runOnUiThread(() -> {
            try {
                binding.resultView.setText("");
                binding.resultView.append("Final Key\n");
                binding.resultView.append(reconstructionDetails.getKey() + "\n");
                binding.resultView.append("Total Shares" + details.getTotalShares() + "\n");
                binding.resultView.append("Required Shares" + details.getThreshold() + "\n");
            } catch (RuntimeError e) {
                renderError(e);
            }
        });

    }

    public String generateRandomPassword(int length) {
        // Define the characters from which the password will be formed
        String allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";

        Random random = new Random();
        StringBuilder password = new StringBuilder();

        // Generate the password by randomly selecting characters from the allowedChars string
        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(allowedChars.length());
            char randomChar = allowedChars.charAt(randomIndex);
            password.append(randomChar);
        }

        return password.toString();
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }

}