using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.IO;
using System.Security.Cryptography;
using System.Text;
namespace Encryption.Controllers
{
    public class EncryptDecryptController : Controller
    {
        // GET: EncryptDecrypt
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Encryption(string InputValue, bool IsEncrypt, string privateKey)
        {
            string result;
            if (IsEncrypt)
            {
                result = Encryption_Decryption.EncryptString(InputValue, privateKey);

            }
            else
            {
                result = Encryption_Decryption.DecryptString(InputValue, privateKey);
            }
            if (result != null)
            {
                return Json(result, JsonRequestBehavior.AllowGet);
            }
            return Json("", JsonRequestBehavior.AllowGet);

        }

    }
    public class Encryption_Decryption
    {

        public static string EncryptString(string Normal_String, string SecretKey)
        {
            try
            {
                string Encrypted_String = null;
                byte[][] keys = GetHashKeys(SecretKey);
                try
                {
                    Encrypted_String = EncryptStringToBytes_Aes(Normal_String, keys[0], keys[1]);
                }
                catch (CryptographicException) { }
                catch (ArgumentNullException) { }
                return Encrypted_String;
            }
            catch (Exception ex)
            {
                ex.Message.ToString();
                return null;
            }
        }

        public static string DecryptString(string Encrypted_String, string SecretKey)
        {
            try
            {
                if (Encrypted_String != null)
                {
                    string key = SecretKey;

                    string decData = null;
                    byte[][] keys = GetHashKeys(key);
                    try
                    {
                        decData = DecryptStringFromBytes_Aes(Encrypted_String, keys[0], keys[1]);
                    }
                    catch (CryptographicException) { }
                    catch (ArgumentNullException) { }
                    if (decData == null)
                        return "";
                    else
                        return decData;
                }
                else
                    return "";
            }
            catch (Exception ex)
            {
                return "";
            }
        }

        public static byte[][] GetHashKeys(string key)
        {
            try
            {
                byte[][] result = new byte[2][];
                Encoding enc = Encoding.UTF8;
                SHA256 sha2 = new SHA256CryptoServiceProvider();
                byte[] rawKey = enc.GetBytes(key);
                byte[] rawIV = enc.GetBytes(key);
                byte[] hashKey = sha2.ComputeHash(rawKey);
                byte[] hashIV = sha2.ComputeHash(rawIV);
                Array.Resize(ref hashIV, 16);
                result[0] = hashKey;
                result[1] = hashIV;
                sha2.Clear();
                sha2.Dispose();
                return result;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public static string EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            try
            {
                if (plainText == null || plainText.Length <= 0)
                    throw new ArgumentNullException("plainText");
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");
                byte[] encrypted;
                using (AesManaged aesAlg = new AesManaged())
                {
                    aesAlg.Key = Key;
                    aesAlg.IV = IV;
                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(plainText);
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                    aesAlg.Clear();
                    aesAlg.Dispose();
                }
                return Convert.ToBase64String(encrypted);
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public static string DecryptStringFromBytes_Aes(string cipherTextString, byte[] Key, byte[] IV)
        {
            try
            {
                cipherTextString = cipherTextString.Replace(" ", "+");
                byte[] cipherText = Convert.FromBase64String(cipherTextString);
                if (cipherText == null || cipherText.Length <= 0)
                    throw new ArgumentNullException("cipherText");
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");
                string plaintext = null;
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Key;
                    aesAlg.IV = IV;
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                    aesAlg.Clear();
                    aesAlg.Dispose();
                }
                return plaintext;
            }
            catch (Exception ex)
            {
                return null;
            }
        }
    }
}