package com.microsoft.cordova;

import android.app.Activity;
import android.content.res.AssetManager;

import org.json.JSONArray;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Utilities class used for native operations related to calculating hashes of update contents.
 */
public class UpdateHashUtils {
    private static final Set<String> ignoredFiles = new HashSet<String>(Arrays.asList(
            ".codepushrelease",
            ".DS_Store"
    ));

    public static String getBinaryHash(Activity activity) throws IOException, NoSuchAlgorithmException {
        return getHashForPath(activity, null);
    }

    public static String getHashForPath(Activity activity, String path) throws IOException, NoSuchAlgorithmException {
        ArrayList<String> manifestEntries = new ArrayList<String>();
        if (path == null) {
            addFolderEntriesToManifest(manifestEntries, "www", "www", activity.getAssets());
        } else {
            File basePath = activity.getApplicationContext().getFilesDir();
            File fullPath = new File(basePath, path);
            addFolderEntriesToManifest(manifestEntries, "www", fullPath.getPath(), null);
        }
        Collections.sort(manifestEntries);
        JSONArray manifestJSONArray = new JSONArray();
        for (String manifestEntry : manifestEntries) {
            manifestJSONArray.put(manifestEntry);
        }

        // The JSON serialization turns path separators into "\/", e.g. "www\/images\/image.png"
        String manifestString = manifestJSONArray.toString().replace("\\/", "/");
        return computeHash(new ByteArrayInputStream(manifestString.getBytes()));
    }

    private static void addFolderEntriesToManifest(ArrayList<String> manifestEntries, String prefix, String path, AssetManager assetManager) throws IOException, NoSuchAlgorithmException {
        String[] fileList;
        if (assetManager != null) {
            fileList = assetManager.list(path);
        } else {
            fileList = new File(path).list();
        }
        if (fileList != null && fileList.length > 0) {
            // This is a folder, recursively add folder entries to the manifest.
            for (String pathInFolder : fileList) {
                if (UpdateHashUtils.ignoredFiles.contains(pathInFolder)) {
                    continue;
                }
                String relativePath = new File(prefix, pathInFolder).getPath();
                String absolutePath = new File(path, pathInFolder).getPath();
                addFolderEntriesToManifest(manifestEntries, relativePath, absolutePath, assetManager);
            }
        } else {
            // This is a file, compute a hash and create a manifest entry for it.
            InputStream inputStream;
            if (assetManager != null) {
                inputStream = assetManager.open(path);
            } else {
                inputStream = new FileInputStream(path);
            }
            manifestEntries.add(new File(prefix, new File(path).getName()).getPath() + ":" + computeHash(inputStream));
        }
    }

    private static String computeHash(InputStream dataStream) throws IOException, NoSuchAlgorithmException {
        MessageDigest messageDigest = null;
        DigestInputStream digestInputStream = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            digestInputStream = new DigestInputStream(dataStream, messageDigest);
            byte[] byteBuffer = new byte[1024 * 8];
            while (digestInputStream.read(byteBuffer) != -1);
        } finally {
            try {
                if (digestInputStream != null) digestInputStream.close();
                if (dataStream != null) dataStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        byte[] hash = messageDigest.digest();
        return String.format("%064x", new java.math.BigInteger(1, hash));
    }

}
