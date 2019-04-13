package com.instacart.library.truetime;

import android.content.Context;
import android.os.Environment;
import android.provider.Settings;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MoreSecureCacheImpl implements CacheInterface {

    private static final String TAG = TrueTime.class.getSimpleName();

    private static String PATH_MORE_SECURE_CACHE_FILE;

    //Hard coded since the encoded file doesn't need to be secure, just unreadable for a human
    //(You would need a rooted device and reverse the parsing and checksum algorithm to fool this cache)
    // => not very secure but pretty good for most use cases
    private static final byte[] MORE_SECURE_CACHE_KEY = new byte[] { (byte)105, (byte)168, (byte)167, (byte)105, (byte)43, (byte)128, (byte)164, (byte)250, (byte)54, (byte)37, (byte)124, (byte)135, (byte)173, (byte)237, (byte)140, (byte)145 };
    private static final byte[] MORE_SECURE_CACHE_IV = new byte[] { (byte)70, (byte)156, (byte)165, (byte)150, (byte)87, (byte)248, (byte)4, (byte)213, (byte)89, (byte)97, (byte)102, (byte)227, (byte)178, (byte)132, (byte)8, (byte)207 };

    private Map<String, Long> keyValueMap = new HashMap<>();

    public class SaveContainer{

        public Map<String, Long> KeyValueMap;
        public byte[] Checksum;

        public SaveContainer(Map<String, Long> keyValueMap, byte[] checksum){
            this.KeyValueMap = keyValueMap;
            this.Checksum = checksum;
        }
    }

    public MoreSecureCacheImpl(Context context){

        PATH_MORE_SECURE_CACHE_FILE = context.getFilesDir().getPath() + "/tt.dat";

        LoadValues();
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

        File file = new File(PATH_MORE_SECURE_CACHE_FILE);

        if (file.exists()){

            if(!file.delete()){
                TrueLog.e(TAG, "MoreSecureCacheImpl: clear() Save file deletion failed!");
            }
        }
    }

    @Override
    public void flush() {
        SaveValues();
    }

    private void LoadValues(){

        File file = new File(PATH_MORE_SECURE_CACHE_FILE);

        if (file.exists()){
            //TrueLog.v(TAG, "MoreSecureCacheImpl: LoadValues() file exits");
            try{

                FileInputStream fileInputStream = new FileInputStream(PATH_MORE_SECURE_CACHE_FILE);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(MORE_SECURE_CACHE_KEY, "AES"), new IvParameterSpec(MORE_SECURE_CACHE_IV));
                CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);

                InputStreamReader inputStreamReader = new InputStreamReader(cipherInputStream, "UTF-8");

                SaveContainer saveContainer = null;
                try{
                    Gson gson = new Gson();
                    saveContainer = gson.fromJson(inputStreamReader, SaveContainer.class);

                }catch (Exception e){
                    TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() Gson: error occurred while deserializing!", e);
                }

                if (saveContainer != null){
                    byte[] checksum = CalculateChecksum(saveContainer.KeyValueMap);

                    if (Arrays.equals(checksum, saveContainer.Checksum)){

                        keyValueMap = saveContainer.KeyValueMap;

                    }else{
                        TrueLog.w(TAG, "MoreSecureCacheImpl: LoadValues() checksums aren't matching! Resetting...");

                        //Reset all values since the save file is invalid
                        keyValueMap.clear();

                        if(!file.delete()){
                            TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() Save file deletion failed!");
                        }
                    }
                }else{
                    TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() fromJson() returned null");

                    keyValueMap.clear();
                }

                try{
                    inputStreamReader.close();
                    cipherInputStream.close();
                    fileInputStream.close();

                }catch (IOException e){
                    TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() IOException while closing streams", e);
                }

            }catch (FileNotFoundException e){
                TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() FileNotFoundException", e);
            }catch (NoSuchAlgorithmException e){
                TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() NoSuchAlgorithmException", e);
            }catch (NoSuchPaddingException e){
                TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() NoSuchAlgorithmException", e);
            }catch (InvalidAlgorithmParameterException e){
                TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() InvalidAlgorithmParameterException", e);
            }catch (InvalidKeyException e){
                TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() InvalidKeyException", e);
            }catch (UnsupportedEncodingException e){
                TrueLog.e(TAG, "MoreSecureCacheImpl: LoadValues() UnsupportedEncodingException", e);
            }

        }else{
            //TrueLog.v(TAG, "MoreSecureCacheImpl: LoadValues() file doesn't exit");
            keyValueMap.clear();
        }
    }

    private void SaveValues(){

        try{

            FileOutputStream fileOutputStream = new FileOutputStream(PATH_MORE_SECURE_CACHE_FILE);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(MORE_SECURE_CACHE_KEY, "AES"), new IvParameterSpec(MORE_SECURE_CACHE_IV));
            CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, cipher);

            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(cipherOutputStream, "UTF-8");

            byte[] checksum = CalculateChecksum(keyValueMap);
            SaveContainer saveContainer = new SaveContainer(keyValueMap, checksum);

            try{
                Gson gson = new Gson();
                gson.toJson(saveContainer, SaveContainer.class, outputStreamWriter);

                //TrueLog.v(TAG, "MoreSecureCacheImpl: SaveValues() toJson: " + gson.toJson(saveContainer, SaveContainer.class));
            }catch (Exception e){
                TrueLog.e(TAG, "MoreSecureCacheImpl: SaveValues() Gson: error occurred while serializing!", e);
            }

            try{
                outputStreamWriter.close();
                cipherOutputStream.close();
                fileOutputStream.close();

            }catch (IOException e){
                TrueLog.e(TAG, "MoreSecureCacheImpl: SaveValues() IOException while closing streams", e);
            }
            //TrueLog.v(TAG, "MoreSecureCacheImpl: SaveValues() successfully saved");

        }catch (FileNotFoundException fileNotFoundException){
            TrueLog.e(TAG, "MoreSecureCacheImpl: SaveValues() FileNotFoundException", fileNotFoundException);
        }catch (NoSuchAlgorithmException noSuchAlgorithmException){
            TrueLog.e(TAG, "MoreSecureCacheImpl: SaveValues() NoSuchAlgorithmException", noSuchAlgorithmException);
        }catch (NoSuchPaddingException noSuchPaddingException){
            TrueLog.e(TAG, "MoreSecureCacheImpl: SaveValues() NoSuchAlgorithmException", noSuchPaddingException);
        }catch (InvalidAlgorithmParameterException e){
            TrueLog.e(TAG, "MoreSecureCacheImpl: SaveValues() InvalidAlgorithmParameterException", e);
        }catch (InvalidKeyException e){
            TrueLog.e(TAG, "MoreSecureCacheImpl: SaveValues() InvalidKeyException", e);
        }catch (UnsupportedEncodingException e){
            TrueLog.e(TAG, "MoreSecureCacheImpl: SaveValues() UnsupportedEncodingException", e);
        }
    }

    private byte[] CalculateChecksum(Map<String, Long> map){

        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-1");

            for (Map.Entry<String, Long> entry : map.entrySet()) {

                digest.update((entry.getKey() + entry.getValue()).getBytes());
            }

            return digest.digest();

        }catch (NoSuchAlgorithmException e){
            TrueLog.e(TAG, "MoreSecureCacheImpl: CalculateChecksum() NoSuchAlgorithmException", e);

            return new byte[0];
        }
    }
}
