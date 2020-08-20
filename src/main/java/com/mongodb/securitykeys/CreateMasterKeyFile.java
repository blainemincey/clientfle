package com.mongodb.securitykeys;

import io.github.cdimascio.dotenv.Dotenv;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

/**
 *
 */
public class CreateMasterKeyFile {

    private String masterKeyFile;

    /**
     *
     */
    public CreateMasterKeyFile() {
        // load .env properties
        Dotenv dotenv = Dotenv.configure().load();

        // MongoDB Variables
        this.masterKeyFile = dotenv.get("MASTER_KEY_FILE");

        System.out.println("Create master key file.");
        this.createFile();
    }

    /**
     *
     */
    private void createFile() {
        byte[] localMasterKey = new byte[96];
        new SecureRandom().nextBytes(localMasterKey);

        try (FileOutputStream stream = new FileOutputStream(this.masterKeyFile)) {
            stream.write(localMasterKey);
        } catch(IOException ioe) {
            System.err.println("Exception creating master key: " + ioe);
        }

        System.out.println(this.masterKeyFile + " created successfully.");
    }

    /**
     *
     * @param args
     */
    public static void main(String[] args) {
        new CreateMasterKeyFile();
    }
}
