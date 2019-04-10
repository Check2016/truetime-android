package com.instacart.library.truetime;

import android.content.Context;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MoreSecureCacheImpl implements CacheInterface {

    private static final String TAG = TrueTime.class.getSimpleName();

    private static String PATH_MORE_SECURE_CACHE_FILE;
    private static final byte[] MORE_SECURE_CACHE_KEY = new byte[] { (byte)105, (byte)168, (byte)167, (byte)105, (byte)43, (byte)128, (byte)164, (byte)250, (byte)54, (byte)37, (byte)124, (byte)135, (byte)173, (byte)237, (byte)140, (byte)145 };
    private static final byte[] MORE_SECURE_CACHE_IV = new byte[] { (byte)70, (byte)156, (byte)165, (byte)150, (byte)87, (byte)248, (byte)4, (byte)213, (byte)89, (byte)97, (byte)102, (byte)227, (byte)178, (byte)132, (byte)8, (byte)207 };

    private Map<String, Long> keyValueMap;

    public MoreSecureCacheImpl(Context context){

        PATH_MORE_SECURE_CACHE_FILE = context.getFilesDir().getPath() + "/tt.dat";
    }

    @Override
    public void put(String key, long value) {
        keyValueMap.put(key, value);
    }

    @Override
    public long get(String key, long defaultValue) {

        Long value = keyValueMap.get(key);

        if (value != null){
            return value;
        }else{
            return defaultValue;
        }
    }

    @Override
    public void clear() {
        keyValueMap.clear();
    }

    private void LoadValues(){

        File file = new File(PATH_MORE_SECURE_CACHE_FILE);

        if (file.exists()){

            try{

                FileInputStream fileInputStream = new FileInputStream(PATH_MORE_SECURE_CACHE_FILE);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec((MORE_SECURE_CACHE_KEY, "AES"), new IvParameterSpec(MORE_SECURE_CACHE_IV)));
                CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);

                InputStreamReader inputStreamReader = new InputStreamReader(cipherInputStream);

                Gson gson = new Gson();
                Type keyValueMapType = new TypeToken<Map<String, Long>>() {}.getType();
                Map<String, Long> newKeyValueMap = gson.fromJson(inputStreamReader, keyValueMapType);

                if (newKeyValueMap != null){
                    keyValueMap = newKeyValueMap;
                }else{
                    TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() fromJson() returned null");
                }

            }catch (FileNotFoundException fileNotFoundException){
                TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() FileNotFoundException", fileNotFoundException);
            }catch (NoSuchAlgorithmException noSuchAlgorithmException){
                TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() NoSuchAlgorithmException", noSuchAlgorithmException);
            }catch (NoSuchPaddingException noSuchPaddingException){
                TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() NoSuchAlgorithmException", noSuchPaddingException);
            }

        }else{
            keyValueMap.clear();
        }
    }
}
