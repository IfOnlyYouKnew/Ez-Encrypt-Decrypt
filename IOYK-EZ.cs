using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Security;
using System.Diagnostics;
using System.Net.Http;
using System.Windows.Forms;

    namespace Ez
    {

        public static partial class Run 
        {
                private static string inputFile;
                private static string encryptedFile;
                private static string keyFile;
                private static string ivFile;
                private static string cipherFile;
                private static string cipherKeyFile;
                private static string cipherSecretKey;

                public static void Encrypt(string yourFile, string newFile) 
                {
                     inputFile = yourFile;
                     encryptedFile = newFile;
                     keyFile = AppDomain.CurrentDomain.BaseDirectory + "KeyStorage\\" + inputFile.Substring(inputFile.LastIndexOf(@"\")) + @"_key.txt";
                     ivFile = AppDomain.CurrentDomain.BaseDirectory + "KeyStorage\\" + inputFile.Substring(inputFile.LastIndexOf(@"\")) + @"_iv.txt";
                     EncryptFile(inputFile, encryptedFile, keyFile, ivFile);     
                }

                static void EncryptFile(string inputFile, string encryptedFile, string keyFile, string ivFile)
                {
                     new FileIOPermission(PermissionState.Unrestricted).Assert();
                     using (Aes aes = Aes.Create())
                     {
                         aes.KeySize = 256;
                         aes.BlockSize = 128;
                         aes.Padding = PaddingMode.PKCS7;

                            aes.GenerateKey();
                            aes.GenerateIV();

                              byte[] key = aes.Key;
                              byte[] iv = aes.IV;

                                 File.WriteAllBytes(keyFile, key);
                                 File.WriteAllBytes(ivFile, iv);

                         using (FileStream inputStream = new FileStream(inputFile, FileMode.Open))
                         {
                                using (FileStream encryptedStream = new FileStream(encryptedFile, FileMode.Create))
                                {
                                   using (CryptoStream cryptoStream = new CryptoStream(encryptedStream, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write)){ inputStream.CopyTo(cryptoStream); }
                                }
                         }

                     }

                     CodeAccessPermission.RevertAssert();
                }

                public static async void Decrypt(string encryptedFile, string keyFile, string ivFile)
                {
                       byte[] key = File.ReadAllBytes(keyFile);
                       byte[] iv = File.ReadAllBytes(ivFile);

                       if (encryptedFile.Contains("http"))
                       {
                            using (HttpClient client = new HttpClient())
                            {
                                byte[] fileBytes = await client.GetByteArrayAsync(encryptedFile);

                                 SaveFileDialog saveFileDialog = new SaveFileDialog();
                                 saveFileDialog.Filter = "Html Files (*.html)|*.html|Javascript Files (*.js)|*.js|CSS Files (*.css)|*.css|All Files (*.*)|*.*";
                                 saveFileDialog.FilterIndex = 1;

                                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                                    {
                                         File.WriteAllBytes(saveFileDialog.FileName, fileBytes);
                                         encryptedFile = saveFileDialog.FileName;
                                    }
                            }
                       }

                       await Task.Delay(1200);

                       using (Aes aes = Aes.Create())
                       {
                             aes.Key = key;
                             aes.IV = iv;
                             aes.Padding = PaddingMode.PKCS7;
                            
                             new FileIOPermission(PermissionState.Unrestricted).Assert();
                             using (FileStream encryptedStream = new FileStream(encryptedFile, FileMode.Open))
                             {
                                await Task.Delay(700);
                   
                                    using (FileStream decryptedStream = new FileStream(inputFile.Substring(0, inputFile.LastIndexOf(@"\")) + inputFile.Substring(inputFile.LastIndexOf(@"\"), inputFile.LastIndexOf(@".") - inputFile.LastIndexOf(@"\")) + "_dec" + inputFile.Substring(inputFile.LastIndexOf(@".")), FileMode.Create))
                                    {
                                         using (CryptoStream cryptoStream = new CryptoStream(encryptedStream, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read)){ cryptoStream.CopyTo(decryptedStream); }
                                    }
                             }
                                 //Uncomment to allow decrypted file to attempt to run afterward
                                 //CodeAccessPermission.RevertAssert();
                                 //Process process = new Process();
                                // process.StartInfo.FileName = inputFile.Substring(0, inputFile.LastIndexOf(@"\")) + inputFile.Substring(inputFile.LastIndexOf(@"\"), inputFile.LastIndexOf(@".") - inputFile.LastIndexOf(@"\")) + "_dec" + inputFile.Substring(inputFile.LastIndexOf(@"."));
                                // process.Start();

                       }
                }

        }
    
    }

