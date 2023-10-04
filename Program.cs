using System.Collections;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;


class Program
{
    private static string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static EncryptedData encryptedData;

    static void Main(string[] args)
    {
        LoadEncryptedData();


        Console.WriteLine("Choose an action:");
        Console.WriteLine("1. Encrypt a message and save it in a file");
        Console.WriteLine("2. Decrypt and show text from the file");

        string action = Console.ReadLine();

        switch (action)
        {
            case "1":
                EncryptAndSave();
                break;
            case "2":
                DecryptAndShow();
                break;
            default:
                Console.WriteLine("Invalid choice.");
                break;
        }
    }


    static void EncryptAndSave()
    {
        Console.Write("Enter a 16 characters passphrase: ");
        string passphrase = Console.ReadLine();

        if (passphrase.Length != 16)
        {
            Console.WriteLine("You entered a passphrase with an incorrect number of characters, must be 16");
            return;
        }

        byte[] salt = GenerateSalt();

        Console.WriteLine("Write message to encrypt");
        string message = Console.ReadLine();

        byte[] key = HashPassphrase(passphrase, salt);

        using var aes = new AesGcm(key);
        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // MaxSize = 12
        RandomNumberGenerator.Fill(nonce);
        var plaintextBytes = Encoding.UTF8.GetBytes(message);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // MaxSize = 16
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);


        encryptedData = new EncryptedData
        {
            Nonce = nonce,
            Salt = salt,
            Ciphertext = ciphertext,
            Tag = tag
        };

        string jsonData = JsonConvert.SerializeObject(encryptedData);
        File.WriteAllText(Path.Combine(docPath, "EncryptedFile.json"), jsonData);
        Console.WriteLine("Message encrypted and saved to file.");
    }


    static void DecryptAndShow()
    {
        if (encryptedData.Ciphertext == null)
        {
            Console.WriteLine(
                "No encrypted data found. Please choose option 1 to encrypt a message first.");
            return;
        }

        Console.Write("Enter a 16 characters passphrase: ");
        string passphrase = Console.ReadLine();

        if (passphrase.Length != 16)
        {
            Console.WriteLine("You entered a passphrase with an incorrect number of characters, must be 16");
            return;
        }
        
        byte[] key = HashPassphrase(passphrase, encryptedData.Salt);

        string filePath = Path.Combine(docPath, "EncryptedFile.json");
        string jsonData = File.ReadAllText(filePath);
        

        try
        {
            using (var aes = new AesGcm(key))
            {
                var plaintextBytes = new byte[encryptedData.Ciphertext.Length];
                aes.Decrypt(encryptedData.Nonce, encryptedData.Ciphertext, encryptedData.Tag, plaintextBytes);

                var decryptedMessage = Encoding.UTF8.GetString(plaintextBytes);
                Console.WriteLine("Decrypted Message:");
                Console.WriteLine(decryptedMessage);
            }
        }
        catch (CryptographicException)
        {
            Console.WriteLine("Decryption failed. Incorrect passphrase.");
        }
        catch (IOException e)
        {
            Console.WriteLine("The file could not be read:");
            Console.WriteLine(e.Message);
        }
    }

    /**
       * class that stores the encrypted data in the json file
       */
    public class EncryptedData
    {
        public byte[] Nonce { get; set; }
        public byte[] Salt { get; set; } //init, get
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

    private static byte[] GenerateSalt()
    {
        byte[] salt = new byte[16];
        using (var random = new RNGCryptoServiceProvider())
        {
            random.GetBytes(salt);
        }

        return salt;
    }

    
    private static byte[] HashPassphrase(string passphrase, byte[] salt)
    {
        using (var pbkdf2 = new Rfc2898DeriveBytes(passphrase, salt, 10000, HashAlgorithmName.SHA256))
        {
            return pbkdf2.GetBytes(32);
        }
    }
}