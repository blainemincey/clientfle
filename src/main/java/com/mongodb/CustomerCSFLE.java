package com.mongodb;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import static com.mongodb.client.model.Filters.*;

import com.mongodb.utils.CSFLEHelpers;
import com.mongodb.model.CustomerDocument;
import io.github.cdimascio.dotenv.Dotenv;
import org.bson.Document;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.codecs.pojo.PojoCodecProvider;
import org.bson.types.Binary;
import static org.bson.codecs.configuration.CodecRegistries.fromProviders;
import static org.bson.codecs.configuration.CodecRegistries.fromRegistries;

public class CustomerCSFLE {

    // MongoDB variables
    private String mongodbConnection;
    private String database;
    private String collection;

    // Variables related to client-side field-level encryption
    private String keyDb;
    private String keyCollection;
    private String kmsProvider;
    private String keyAltName;
    private String masterKeyFile;
    private byte[] masterKeyBytes;
    private String encryptionKey;
    private String mongocryptdPath;

    // Helper class with majority of encryption methods
    CSFLEHelpers helper = new CSFLEHelpers();

    // class var for encrypted customer document
    CustomerDocument encryptedCustomerDocument;

    /**
     *
     */
    public CustomerCSFLE() {
        this.initialize();
    }

    /**
     *
     */
    private void initialize() {
        System.out.println("Initialize from .env properties");

        // load .env properties
        Dotenv dotenv = Dotenv.configure().load();

        // MongoDB Variables
        this.mongodbConnection = dotenv.get("CONNECTION");
        this.database = dotenv.get("DATABASE");
        this.collection = dotenv.get("COLLECTION");

        // CSFLE Variables from .env
        this.keyDb = dotenv.get("KEY_DB");
        this.keyCollection = dotenv.get("KEY_COLLECTION");
        this.kmsProvider = dotenv.get("KMS_PROVIDER");
        this.keyAltName = dotenv.get("KEY_ALT_NAME");
        this.masterKeyFile = dotenv.get("MASTER_KEY_FILE");
        this.mongocryptdPath = dotenv.get("MONGO_CRYPTD_PATH");

        // Init encryption key
        this.initEncryptionKey();

        // verify encryption key to continue
        if(this.encryptionKey == null || this.encryptionKey.length() < 1) {
            System.err.println("Improper Encryption Key.  Halting.");
            System.err.println("Encryption Key: " + this.encryptionKey);
        } else {
            System.out.println("Encryption Key set.  Continue.");

            // Run Encrypted Client
            this.encryptedClient();

            // Normal Client
            this.normalClient();

            // Query encrypted doc to display cyphertext
            this.normalClientCypherText();
        }
    }

    /**
     *
     */
    private void initEncryptionKey() {
        System.out.println("=== Initialize Encrypted Key ===");
        try {
            System.out.println("Read master key file");
            this.masterKeyBytes = helper.readMasterKey(this.masterKeyFile);

        } catch (Exception e) {
            System.err.println("Exception reading master key: " + e);
        }

        System.out.println("Find data encryption key");
        this.encryptionKey = CSFLEHelpers.findDataEncryptionKey(  this.mongodbConnection,
                                                                    this.keyAltName,
                                                                    this.keyDb,
                                                                    this.keyCollection);

        if (this.encryptionKey == null && masterKeyBytes.length > 0) {
            // No key found; create index on key vault and a new encryption key and print the key
            CSFLEHelpers.createKeyVaultIndex(this.mongodbConnection, this.keyDb, this.keyCollection);
            String keyVaultCollection = String.join(".", this.keyDb, this.keyCollection);
            this.encryptionKey = CSFLEHelpers.createDataEncryptionKey(  this.mongodbConnection,
                                                                        this.kmsProvider,
                                                                        this.masterKeyBytes,
                                                                        keyVaultCollection,
                                                                        keyAltName);

            System.out.println("Created new encryption key: " + this.encryptionKey);
        } else {
            // Print the key
            System.out.println("Found existing encryption key: " + this.encryptionKey);
        }
    }

    /**
     *
     */
    private void encryptedClient() {
        try {
            System.out.println("\n=== Encrypted Client ===");

            String keyVaultCollection = String.join(".", this.keyDb, this.keyCollection);

            Document schema = CSFLEHelpers.createJSONSchema(this.encryptionKey);

            MongoClient encryptedClient = CSFLEHelpers.createEncryptedClient(
                    this.mongodbConnection,
                    this.kmsProvider,
                    this.masterKeyBytes,
                    keyVaultCollection,
                    schema,
                    this.mongocryptdPath,
                    this.database,
                    this.collection);

            MongoCollection<CustomerDocument> encryptedCollection =
                    encryptedClient.getDatabase(this.database).getCollection(this.collection,CustomerDocument.class);

            CustomerDocument customerDocument = new CustomerDocument();

            encryptedCollection.insertOne(customerDocument);
            System.out.println("Query encrypted SSN: " + customerDocument.getSsn());

            // set class variable to use in other methods
            this.encryptedCustomerDocument = customerDocument;

            CustomerDocument encryptDocument = encryptedCollection.find(new Document("ssn", customerDocument.getSsn())).first();
            System.out.println(encryptDocument + "\n");

            encryptedClient.close();

        } catch (Exception e) {
            System.err.println(e);
        }
    }

    /**
     *
     */
    private void normalClient() {
        System.out.println("=== Normal Client ===");

        CodecRegistry pojoCodecRegistry = fromRegistries(MongoClientSettings.getDefaultCodecRegistry(),
                fromProviders(PojoCodecProvider.builder().automatic(true).build()));

        MongoClientSettings settings = MongoClientSettings.builder()
                .codecRegistry(pojoCodecRegistry)
                .applyConnectionString(new ConnectionString(this.mongodbConnection))
                .build();

        MongoClient normalClient = MongoClients.create(settings);
        MongoCollection<CustomerDocument> normalCollection =
                normalClient.getDatabase(this.database).getCollection(this.collection,CustomerDocument.class);

        CustomerDocument customerDocument = new CustomerDocument();

        normalCollection.insertOne(customerDocument);
        System.out.println("Query normal SSN: " + customerDocument.getSsn());
        CustomerDocument normalDocument = normalCollection.find(new Document("ssn", customerDocument.getSsn())).first();
        System.out.println(normalDocument + "\n");

        System.out.println("\nQuery with the earlier encrypted SSN with NORMAL client: " + this.encryptedCustomerDocument.getSsn());
        CustomerDocument encryptedSsnWithNormalClient = normalCollection.find(new Document("ssn", this.encryptedCustomerDocument.getSsn())).first();
        System.out.println(encryptedSsnWithNormalClient);

        normalClient.close();
    }

    /**
     *
     */
    private void normalClientCypherText() {
        System.out.println("\n=== Normal Client & Display CypherText ===");
        MongoClientSettings settings = MongoClientSettings.builder()
                .applyConnectionString(new ConnectionString(this.mongodbConnection))
                .build();

        MongoClient normalClientCypher = MongoClients.create(settings);
        MongoCollection myCollection =
                normalClientCypher.getDatabase(this.database).getCollection(this.collection);

        Document myDoc = (Document) myCollection.find(eq("_id", this.encryptedCustomerDocument.getId())).first();
        System.out.println(myDoc.toJson() + "\n");

        // Display the specific fields with the cypher text
        System.out.println("Specific encrypted fields:");
        Binary ssn = myDoc.get("ssn", org.bson.types.Binary.class);
        Binary prescription = myDoc.get("prescription", org.bson.types.Binary.class);

        System.out.println("SSN: " + new String(ssn.getData()));
        System.out.println("Prescription: " + new String(prescription.getData()));
    }

    /**
     *
     * @param args
     */
    public static void main(String[] args) {
        new CustomerCSFLE();
    }
}
