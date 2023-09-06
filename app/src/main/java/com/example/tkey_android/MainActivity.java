package com.example.tkey_android;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;

import com.google.android.material.snackbar.Snackbar;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import androidx.navigation.NavController;
import androidx.navigation.Navigation;
import androidx.navigation.ui.AppBarConfiguration;
import androidx.navigation.ui.NavigationUI;

import com.example.tkey_android.databinding.ActivityMainBinding;
import com.web3auth.tkey.ThresholdKey.ServiceProvider;
import com.web3auth.tkey.ThresholdKey.StorageLayer;
import com.web3auth.tkey.ThresholdKey.ThresholdKey;
import com.web3auth.tkey.Version;
import com.web3auth.tkey.RuntimeError;
import android.view.Menu;
import android.view.MenuItem;

import org.torusresearch.customauth.types.TorusVerifierUnionResponse;
import org.torusresearch.torusutils.types.SessionData;

public class MainActivity extends AppCompatActivity {

    public TorusVerifierUnionResponse userInfo;

    public SessionData sessionData;
    
    private AppBarConfiguration appBarConfiguration;

    public ThresholdKey tKey;
    public StorageLayer tkeyStorage;
    public ServiceProvider tkeyProvider;

    public ThresholdKey transferKey;
    public StorageLayer transferStorage;
    public ServiceProvider transferProvider;

    public String postboxKey;

    public SharedPreferences sharedpreferences;

    private static final String PREF_FILE_NAME = "app_shared_preferences";

    public void resetState() {
        this.tKey = null;
        this.tkeyProvider = null;
        this.tkeyStorage = null;
        this.transferKey = null;
        this.transferProvider = null;
        this.transferStorage = null;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        System.loadLibrary("tkey-native");
        String libversion;
        try {
            libversion = Version.current();
        } catch (RuntimeError e) {
            throw new RuntimeException("Not able to load tkey-native", e);
        }

        sharedpreferences = getSharedPreferences(PREF_FILE_NAME,
                Context.MODE_PRIVATE);

        new AlertDialog.Builder(MainActivity.this)
                .setTitle("Native library version")
                .setMessage(libversion)
                .setCancelable(false)
                .setPositiveButton("ok", (dialog, which) -> {
                    // Whatever...
                }).show();

        com.example.tkey_android.databinding.ActivityMainBinding binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        setSupportActionBar(binding.toolbar);

        NavController navController = Navigation.findNavController(this, R.id.nav_host_fragment_content_main);
        appBarConfiguration = new AppBarConfiguration.Builder(navController.getGraph()).build();
        NavigationUI.setupActionBarWithNavController(this, navController, appBarConfiguration);

        binding.fab.setOnClickListener(view -> Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                .setAction("Action", null).show());
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public boolean onSupportNavigateUp() {
        NavController navController = Navigation.findNavController(this, R.id.nav_host_fragment_content_main);
        return NavigationUI.navigateUp(navController, appBarConfiguration)
                || super.onSupportNavigateUp();
    }
}