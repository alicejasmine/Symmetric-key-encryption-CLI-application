using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
//using Symmetric_key;

class Program
{
    private static byte[] key = new byte[32];
    private static string cpf = "password";

    private static string docPath =
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

    private static EncryptedData encryptedData = null;

    static void Main(string[] args)
    {
        LoadEncryptedData();
        Console.WriteLine("Enter the passphrase");
        string pf = Console.ReadLine();


        if (VerifyPassPhrase(pf))
        {
            Console.WriteLine("Choose an action:");
            Console.WriteLine("1. Encrypt text and save in a file");
            Console.WriteLine("2. Decrypt and show text from file");
            string action = Console.ReadLine();


            if (key == null || key.Length != 32)
            {
                Console.WriteLine("Generating encryption key...");
                RandomNumberGenerator.Fill(key);
                Console.WriteLine("Key generated.");
            }


            if (action.Equals("1"))
            {
                //Encrypt and save to file
                Console.WriteLine("Write message to encrypt");

                String message = Console.ReadLine();
                var (ciphertext, nonce, tag) = EncryptMessage(message, key);

                encryptedData = new EncryptedData
                {
                    Nonce = nonce,
                    Ciphertext = ciphertext,
                    Tag = tag
                };


                string jsonData = JsonConvert.SerializeObject(encryptedData);
                File.WriteAllText(Path.Combine(docPath, "EncryptedFile.json"), jsonData);

                Console.WriteLine("Message encrypted and saved to file.");
            }

            if (action.Equals("2"))
            {
                try
                {
                    if (encryptedData == null)
                    {
                        Console.WriteLine(
                            "No encrypted data found. Please choose option 1 to encrypt a message first.");
                    }

                    string filePath = Path.Combine(docPath, "EncryptedFile.json");
                    string jsonData = File.ReadAllText(filePath);


                    var decryptedMessage = Decrypt(encryptedData.Ciphertext, encryptedData.Nonce, encryptedData.Tag,
                        key);
                    Console.WriteLine("Decrypted Message:");
                    Console.WriteLine(decryptedMessage);
                }
                catch (IOException e)
                {
                    Console.WriteLine("The file could not be read:");
                    Console.WriteLine(e.Message);
                }
            }
        }
    }


    public static bool VerifyPassPhrase(string pf)
    {
        if (pf == null)
        {
            Console.WriteLine("Enter a passphrase");
        }

        if (pf.Equals(cpf))
        {
            return true;
        }
        Console.WriteLine("passphrase incorrect");
        return false; 
    }


    private static (byte[] ciphertext, byte[] nonce, byte[] tag) EncryptMessage(string plaintext, byte[] key)
    {
        // Check key length
        if (key.Length != 32) //256-bit key
        {
            throw new ArgumentException("Invalid key length. Key must be 256 bits (32 bytes) long.");
        }
        //RandomNumberGenerator.Fill(key);

        using var aes = new AesGcm(key);

        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // MaxSize = 12
        RandomNumberGenerator.Fill(nonce);


        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // MaxSize = 16
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
        return (ciphertext, nonce, tag);
    }

    private static string Decrypt(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] key)
    {
        using (var aes = new AesGcm(key))
        {
            var plaintextBytes = new byte[ciphertext.Length];

            aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }
    }
    public class EncryptedData
    {
  
        public byte[] Nonce { get; set; }
        public byte[] Ciphertext { get; set; }
        public byte[] Tag { get; set; }
    
    }
    private static void LoadEncryptedData()
    {
        string filePath = Path.Combine(docPath, "EncryptedFile.json");
        if (File.Exists(filePath))
        {
            string jsonData = File.ReadAllText(filePath);
            encryptedData = JsonConvert.DeserializeObject<EncryptedData>(jsonData);
        }
    }
    
    
   
}