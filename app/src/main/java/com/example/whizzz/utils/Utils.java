package com.example.whizzz.utils;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Iterator;

public class Utils {
    //taken from https://stackoverflow.com/a/26709199/14200676
    public static void saveHashMapToPrefs(Context context, String mapPrefName, HashMap<String, String> inputMap) {
        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
        if (sharedPreferences != null) {
            JSONObject jsonObject = new JSONObject(inputMap);
            String jsonString = jsonObject.toString();
            sharedPreferences.edit()
                    .remove(mapPrefName)
                    .putString(mapPrefName, jsonString)
                    .apply();
        }
    }

    //also taken from https://stackoverflow.com/a/26709199/14200676
    public static HashMap<String, String> loadHashMapFromPrefs(Context context, String mapPrefName) {
        HashMap<String, String> outputMap = new HashMap<>();
        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
        try {
            if (sharedPreferences != null) {
                String jsonString = sharedPreferences.getString(mapPrefName, (new JSONObject()).toString());
                if (jsonString != null) {
                    JSONObject jsonObject = new JSONObject(jsonString);
                    Iterator<String> keysItr = jsonObject.keys();
                    while (keysItr.hasNext()) {
                        String key = keysItr.next();
                        String value = jsonObject.getString(key);
                        outputMap.put(key, value);
                    }
                }
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return outputMap;
    }
}
