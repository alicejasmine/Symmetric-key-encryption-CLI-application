using System.Collections;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;


class Program
{
    private static byte[] key = new byte[32];
    private static string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static EncryptedData encryptedData;
    private static byte[] passphraseHash;
    private static byte[] salt;


    static void Main(string[] args)
    {
        LoadEncryptedData();

        if (!File.Exists((Path.Combine(docPath, "EncryptedFile.json"))) || encryptedData.Salt == null ||
            encryptedData.PassphraseHash == null)
        {
            Console.WriteLine("The Passphrase has not been set yet. Please enter a passphrase:");
            string newPf = Console.ReadLine();
            SetPassphrase(newPf);
        }
        else
        {
            Console.WriteLine("Enter the passphrase");
            string inputPf = Console.ReadLine();

            if (!VerifyPassphrase(inputPf, encryptedData.Salt, encryptedData.PassphraseHash))
            {
                Console.WriteLine("The passphrase is not correct.");
                return;
            }

            if (key == null || key.Length != 32)
            {
                RandomNumberGenerator.Fill(key);
            }
        }

        Console.WriteLine("Choose an action:");
        Console.WriteLine("1. Encrypt a message and save it in a file");
        Console.WriteLine("2. Decrypt and show text from the file");

        string action = Console.ReadLine();

        switch (action)
        {
            case "1": //Encrypt and save to file

                Console.WriteLine("Write message to encrypt");
                string message = Console.ReadLine();
                var (ciphertext, nonce, tag) = EncryptMessage(message, key);

                encryptedData.Nonce = nonce;
                encryptedData.Ciphertext = ciphertext;
                encryptedData.Tag = tag;

                string jsonData = JsonConvert.SerializeObject(encryptedData);
                File.WriteAllText(Path.Combine(docPath, "EncryptedFile.json"), jsonData);

                Console.WriteLine("Message encrypted and saved to file.");
                break;

            case "2": //decrypt message and show to terminal
                try
                {
                    if (encryptedData.Ciphertext == null)
                    {
                        Console.WriteLine(
                            "No encrypted data found. Please choose option 1 to encrypt a message first.");
                    }

                    string filePath = Path.Combine(docPath, "EncryptedFile.json");
                    jsonData = File.ReadAllText(filePath);

                    var decryptedMessage =
                        Decrypt(encryptedData.Ciphertext, encryptedData.Nonce, encryptedData.Tag, key);
                    Console.WriteLine("Decrypted Message:");
                    Console.WriteLine(decryptedMessage);
                }
                catch (IOException e)
                {
                    Console.WriteLine("The file could not be read:");
                    Console.WriteLine(e.Message);
                }

                break;

            default:
                Console.WriteLine("The choice submitted is not valid, input either 1 or 2");
                break;
        }
    }

    /**
     * method to set a passphrase the first time the program is run
     */
    private static void SetPassphrase(string passphrase)
    {
        salt = GenerateSalt();
        passphraseHash = HashPassphrase(passphrase, salt);
        encryptedData = new EncryptedData();
        encryptedData.Salt = salt;
        encryptedData.PassphraseHash = passphraseHash;
        string jsonData = JsonConvert.SerializeObject(encryptedData);
        File.WriteAllText(Path.Combine(docPath, "EncryptedFile.json"), jsonData);
    }

    /**
    * method to generate salt and return it
    */
    private static byte[] GenerateSalt()
    {
        byte[] salt = new byte[16];
        using (var random = new RNGCryptoServiceProvider())
        {
            random.GetBytes(salt);
        }

        return salt;
    }

    /**
    * method to verify that the inserted password is the same as the one previously set
    */
    public static bool VerifyPassphrase(string enteredPassphrase, byte[] salt, byte[] storedPassphraseHash)
    {
        byte[] enteredPassphraseHash = HashPassphrase(enteredPassphrase, salt);
        return StructuralComparisons.StructuralEqualityComparer.Equals(enteredPassphraseHash, storedPassphraseHash);
    }

    /**
     * method to derive a cryptographic key from a passphrase and salt as input, using PBKDF2
     */
    private static byte[] HashPassphrase(string passphrase, byte[] salt)
    {
        using (var pbkdf2 = new Rfc2898DeriveBytes(passphrase, salt, 10000, HashAlgorithmName.SHA256))
        {
            return pbkdf2.GetBytes(32);
        }
    }

    /**
      * method to encrypt the message written by the user
      */
    private static (byte[] ciphertext, byte[] nonce, byte[] tag) EncryptMessage(string plaintext, byte[] key)
    {
        if (key.Length != 32)
        {
            throw new ArgumentException("Invalid key length. Key must be 256 bits (32 bytes) long.");
        }

        using var aes = new AesGcm(key);
        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // MaxSize = 12
        RandomNumberGenerator.Fill(nonce);
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // MaxSize = 16
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
        return (ciphertext, nonce, tag);
    }

    /**
     * method to decrypt the message written by the user
     */
    private static string Decrypt(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] key)
    {
        using (var aes = new AesGcm(key))
        {
            var plaintextBytes = new byte[ciphertext.Length];

            aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }
    }

    /**
       * class that stores the encrypted data in the json file
       */
    public class EncryptedData
    {
        public byte[] Nonce { get; set; }
        public byte[] Salt { get; set; } //init, get
        public byte[] PassphraseHash { get; set; }
        public byte[] Ciphertext { get; set; }
        public byte[] Tag { get; set; }
    }

    /**
     * method that loads the encrypted data from the json file to have the updated version of it
     */
    private static void LoadEncryptedData()
    {
        string filePath = Path.Combine(docPath, "EncryptedFile.json");
        if (File.Exists(filePath))
        {
            string jsonData = File.ReadAllText(filePath);
            encryptedData = JsonConvert.DeserializeObject<EncryptedData>(jsonData);
        }
        else
        {
            encryptedData = new EncryptedData();
        }
    }
}