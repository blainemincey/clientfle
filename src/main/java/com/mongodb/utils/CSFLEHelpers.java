package com.mongodb.utils;

import com.mongodb.AutoEncryptionSettings;
import com.mongodb.ClientEncryptionSettings;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.vault.DataKeyOptions;
import com.mongodb.client.vault.ClientEncryption;
import com.mongodb.client.vault.ClientEncryptions;
import org.bson.BsonBinary;
import org.bson.BsonDocument;
import org.bson.Document;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.codecs.pojo.PojoCodecProvider;
import org.bson.conversions.Bson;

import java.io.FileInputStream;
import java.util.*;

import static org.bson.codecs.configuration.CodecRegistries.fromProviders;
import static org.bson.codecs.configuration.CodecRegistries.fromRegistries;

/**
 * Class file developed by MongoDB University w/
 * minor edits.
 * <p>
 * Helper methods and sample data for this companion project.
 */
public class CSFLEHelpers {

    // Reads the 96-byte local master key
    // Reads as resource to keep in line with maven
    public byte[] readMasterKey(String resourceFile) throws Exception {
        int numBytes = 96;
        byte[] fileBytes = new byte[numBytes];

        // uses recent java11 fis.readNBytes
        try (FileInputStream fis = new FileInputStream(resourceFile)) {
            fis.readNBytes(fileBytes, 0, numBytes);
        } catch (Exception e) {
            System.err.println("Read Master Key Exception: " + e);
            fileBytes = null;
        }

        return fileBytes;
    }

    // JSON Schema helpers
    private static Document buildEncryptedField(String bsonType, Boolean isDeterministic) {
        String DETERMINISTIC_ENCRYPTION_TYPE = "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic";
        String RANDOM_ENCRYPTION_TYPE = "AEAD_AES_256_CBC_HMAC_SHA_512-Random";

        return new Document().
                append("encrypt", new Document()
                        .append("bsonType", bsonType)
                        .append("algorithm",
                                (isDeterministic) ? DETERMINISTIC_ENCRYPTION_TYPE : RANDOM_ENCRYPTION_TYPE));
    }

    private static Document createEncryptMetadataSchema(String keyId) {
        List<Document> keyIds = new ArrayList<>();
        keyIds.add(new Document()
                .append("$binary", new Document()
                        .append("base64", keyId)
                        .append("subType", "04")));
        return new Document().append("keyId", keyIds);
    }

    /**
     * Modified method to use SSN and Prescription fields from CustomerDocument custom class.
     *
     * @param keyId
     * @return
     * @throws IllegalArgumentException
     */
    public static Document createJSONSchema(String keyId) throws IllegalArgumentException {
        if (keyId.isEmpty()) {
            throw new IllegalArgumentException("keyId must contain your base64 encryption key id.");
        }
        return new Document().append("bsonType", "object").append("encryptMetadata", createEncryptMetadataSchema(keyId))
                .append("properties", new Document()
                        .append("ssn", buildEncryptedField("string", true))
                        .append("prescription", buildEncryptedField("string", false)));
    }

    // Creates Normal Client
    private static MongoClient createMongoClient(String connectionString) {
        return MongoClients.create(connectionString);
    }

    // Creates KeyVault which allows you to create a key as well as encrypt and decrypt fields
    private static ClientEncryption createKeyVault(String connectionString, String kmsProvider,
                                                   byte[] localMasterKey, String keyVaultCollection) {
        Map<String, Object> masterKeyMap = new HashMap<>();
        masterKeyMap.put("key", localMasterKey);
        Map<String, Map<String, Object>> kmsProviders = new HashMap<>();
        kmsProviders.put(kmsProvider, masterKeyMap);

        ClientEncryptionSettings clientEncryptionSettings = ClientEncryptionSettings.builder()
                .keyVaultMongoClientSettings(MongoClientSettings.builder()
                        .applyConnectionString(new ConnectionString(connectionString))
                        .build())
                .keyVaultNamespace(keyVaultCollection)
                .kmsProviders(kmsProviders)
                .build();

        return ClientEncryptions.create(clientEncryptionSettings);
    }

    /**
     * Modified method to include passing mongocyptdPath variable
     *
     * Creates Encrypted Client which performs automatic encryption and decryption of fields
     *
     *
     * @param connectionString
     * @param kmsProvider
     * @param masterKey
     * @param keyVaultCollection
     * @param schema
     * @param mongocryptdPath
     * @param dataDb
     * @param dataColl
     * @return
     */
    public static MongoClient createEncryptedClient(String connectionString, String kmsProvider,
                                                    byte[] masterKey, String keyVaultCollection,
                                                    Document schema, String mongocryptdPath,String dataDb, String dataColl) {

        String recordsNamespace = dataDb + "." + dataColl;

        Map<String, BsonDocument> schemaMap = new HashMap<>();
        schemaMap.put(recordsNamespace, BsonDocument.parse(schema.toJson()));

        Map<String, Object> keyMap = new HashMap<>();
        keyMap.put("key", masterKey);

        Map<String, Map<String, Object>> kmsProviders = new HashMap<>();
        kmsProviders.put(kmsProvider, keyMap);

        Map<String, Object> extraOpts = new HashMap<>();
        extraOpts.put("mongocryptdSpawnPath", mongocryptdPath);

        // uncomment the following line if you are running mongocryptd manually
        //      extraOpts.put("mongocryptdBypassSpawn", true);

        AutoEncryptionSettings autoEncryptionSettings = AutoEncryptionSettings.builder()
                .keyVaultNamespace(keyVaultCollection)
                .kmsProviders(kmsProviders)
                .extraOptions(extraOpts)
                .schemaMap(schemaMap)
                .build();

        CodecRegistry pojoCodecRegistry = fromRegistries(MongoClientSettings.getDefaultCodecRegistry(),
                fromProviders(PojoCodecProvider.builder().automatic(true).build()));

        MongoClientSettings clientSettings = MongoClientSettings.builder()
                .codecRegistry(pojoCodecRegistry)
                .applyConnectionString(new ConnectionString(connectionString))
                .autoEncryptionSettings(autoEncryptionSettings)
                .build();

        return MongoClients.create(clientSettings);
    }

    // Returns existing data encryption key
    public static String findDataEncryptionKey(String connectionString, String keyAltName, String keyDb, String keyColl) {
        try (MongoClient mongoClient = createMongoClient(connectionString)) {
            Document query = new Document("keyAltNames", keyAltName);
            MongoCollection<Document> collection = mongoClient.getDatabase(keyDb).getCollection(keyColl);
            BsonDocument doc = collection
                    .withDocumentClass(BsonDocument.class)
                    .find(query)
                    .first();

            if (doc != null) {
                return Base64.getEncoder().encodeToString(doc.getBinary("_id").getData());
            }
            return null;
        }
    }

    // Creates index for keyAltNames in the specified key collection
    public static void createKeyVaultIndex(String connectionString, String keyDb, String keyColl) {
        try (MongoClient mongoClient = createMongoClient(connectionString)) {
            MongoCollection<Document> collection = mongoClient.getDatabase(keyDb).getCollection(keyColl);

            Bson filterExpr = Filters.exists("keyAltNames", true);
            IndexOptions indexOptions = new IndexOptions().unique(true).partialFilterExpression(filterExpr);

            collection.createIndex(new Document("keyAltNames", 1), indexOptions);
        }
    }

    // Create data encryption key in the specified key collection
    // Call only after checking whether a data encryption key with same keyAltName exists
    public static String createDataEncryptionKey(String connectionString, String kmsProvider,
                                                 byte[] localMasterKey, String keyVaultCollection, String keyAltName) {
        List<String> keyAltNames = new ArrayList<>();
        keyAltNames.add(keyAltName);

        try (ClientEncryption keyVault = createKeyVault(connectionString, kmsProvider, localMasterKey, keyVaultCollection)) {
            BsonBinary dataKeyId = keyVault.createDataKey(kmsProvider, new DataKeyOptions().keyAltNames(keyAltNames));

            return Base64.getEncoder().encodeToString(dataKeyId.getData());
        }
    }
}
