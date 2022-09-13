using System.Data.SQLite;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Common.Logging;
using System.Net;
using Org.BouncyCastle.Ocsp;

namespace ChromeManager
{
    public class ChromiumCookieReader : IDisposable
    {
        private static ILog s_logger = LogManager.GetLogger(typeof(ChromiumCookieReader));

        /// <summary>
        /// Reading and decrypting Chrome cookies.
        /// <see cref="https://stackoverflow.com/questions/68643057/decrypt-google-cookies-in-c-sharp-net-framework"/>
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="folder"></param>
        /// <returns></returns>
        public List<Cookie> GetCookies(string hostname, string profileFolderPath = null)
        {

            string ChromeCookiePath = profileFolderPath != null
                                            ? System.IO.Path.Combine(profileFolderPath, @"Default\Network\Cookies")
                                            : Environment.ExpandEnvironmentVariables(@"%localappdata%\Google\Chrome\User Data\Default\Network\Cookies");

            
            if (!File.Exists(ChromeCookiePath))
                {
                s_logger.Error($"Cookie database does not exist @ '{ChromeCookiePath}'");
                return new List<Cookie>();
                }
            
            List<Cookie> data = new List<Cookie>();            
            try
            {
                s_logger.Debug($"Reading Cookie database @ '{ChromeCookiePath}'");           
                var connBuilder = new SQLiteConnectionStringBuilder() { 
                                                    DataSource = ChromeCookiePath,
                                                    ReadOnly = true
                                                    };                
                using (var conn = new SQLiteConnection(connBuilder.ConnectionString))
                {
                    conn.Open();
                    //construct the host_key clause for use in the Cookies table query.
                    var subDomains = GetSubDomainList(hostname);
                    var hostClause =  (subDomains.Count > 0) 
                                        ? $"host_key in ('{hostname}', {string.Join(",", subDomains.Select(sub => $"'.{sub}'" ))})"
                                        : $"host_key = '{hostname}'";
            
                    using (var cmd = conn.CreateCommand())
                    {
                        long expireTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                        cmd.CommandText =
                            $@"select   creation_utc,
                                    host_key,
                                    top_frame_site_key,
                                    name,
                                    value,
                                    encrypted_value,
                                    path,
                                    expires_utc,
                                    is_secure,
                                    is_httponly,
                                    last_access_utc,
                                    has_expires,
                                    is_persistent,
                                    priority,
                                    samesite,
                                    source_scheme,
                                    source_port,
                                    is_same_party
                            from cookies
                            WHERE
                            [is_persistent] =1 AND
                            {hostClause}
                            ";

                        byte[] key = AesGcm256.GetKey(profileFolderPath);
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                string name = reader["name"].ToString();
                                string path = reader["path"].ToString();
                                string domain = reader["host_key"].ToString();
                                long expiration = long.Parse(reader["expires_utc"].ToString());
                                byte[] encrypted_value = (byte[])reader["encrypted_value"];
                                string value = DecryptCookieValue(key, encrypted_value);
                                Cookie cookie = new Cookie(name, value, path, domain)
                                    {
                                    Expires = DateTimeOffset.FromUnixTimeSeconds(expiration.ChromiumDbTimeToUnixTime()).DateTime
                                    };
                                data.Add(cookie);
                            }
                        }
                        conn.Close();
                    }
                }
            }
            catch (Exception ex)
            {
                s_logger.Error($"Failure reading cookies from '{ChromeCookiePath}'", ex);
            }
            
            s_logger.Debug($"Cookie count found in database for hostname='{hostname}': {data.Count}");
            return data;
        }

        /// <summary>
        /// Break the host name down into subdomain list.
        /// </summary>
        /// <param name="hostname"></param>
        /// <returns></returns>
        private List<string> GetSubDomainList(string host, bool addHostToList = false)
            {
            if (string.IsNullOrEmpty(host))
                return new List<string>();

           List<string> subDomainList = new List<string>();
           var splits = host.Split(new char[] {'.'}, StringSplitOptions.RemoveEmptyEntries);
           if (splits.Length <= 2)
             return new List<string>();
             
             //ex: www.beta.microsoft.co.uk     
             if (addHostToList)
                subDomainList.Add(host);

             string sub = host;
             for (int i = 0; i < ( splits.Length - 2); i++)
                {
                //sub = twosplit(sub);
                sub = sub.Split(new char[]{'.'}, 2, StringSplitOptions.RemoveEmptyEntries)[1];        
                subDomainList.Add(sub);
                }

            return subDomainList;
            }

        /// <summary>
        /// Decrypt Cookie Value
        /// <see href="https://stackoverflow.com/questions/71718371/decrypt-cookies-encrypted-value-from-chrome-chromium-80-in-c-sharp-issue-wi"/>
        /// <seealso href="https://stackoverflow.com/questions/68643057/decrypt-google-cookies-in-c-sharp-net-framework" />
        /// <seealso href="https://gist.github.com/creachadair/937179894a24571ce9860e2475a2d2ec"/>
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptedCookieValue"></param>
        /// <returns></returns>
        private string DecryptCookieValue(byte[] key, byte[] encryptedCookieValue)
        {
            try
            {
                byte[] nonce, ciphertextTag;
                AesGcm256.prepare(encryptedCookieValue, out nonce, out ciphertextTag);
                string value = AesGcm256.decrypt(ciphertextTag, key, nonce);
                return value;

            }
            catch (Exception ex)
            {
                s_logger.Error("Error encountered decrypting cookie value", ex);
            }

            return null;
        }

        #region Dispose

        /// <summary>
        /// Dispose
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Dispose
        /// </summary>
        protected virtual void Dispose(bool disposable)
        {
            if (disposable)
            { //Dispose of Native
            }
        }

        #endregion

        /// <summary>
        /// AES GCM Decryption Class
        /// </summary>
        class AesGcm256
        {
            /// <summary>
            /// Get the cookie key value.
            /// </summary>
            /// <param name="profileFolderPath"> Path to profile folder. If null, uses the default Chrome folder</param>
            /// <returns></returns>
            public static byte[] GetKey(string profileFolderPath = null)
            {
                string sR = string.Empty;
                string path = profileFolderPath != null
                                   ? System.IO.Path.Combine(profileFolderPath, @"Local State")
                                   : Environment.ExpandEnvironmentVariables(@"%localappdata%\Google\Chrome\User Data\Local State");


                string v = File.ReadAllText(path);

                dynamic json = JsonConvert.DeserializeObject(v);
                string key = json.os_crypt.encrypted_key;

                byte[] src = Convert.FromBase64String(key);
                byte[] encryptedKey = src.Skip(5).ToArray();

                byte[] decryptedKey = ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);

                return decryptedKey;
            }

            public static string decrypt(byte[] encryptedBytes, byte[] key, byte[] iv)
            {
                string sR = String.Empty;
                try
                {
                    GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
                    AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, iv, null);

                    cipher.Init(false, parameters);
                    byte[] plainBytes = new byte[cipher.GetOutputSize(encryptedBytes.Length)];
                    Int32 retLen = cipher.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, plainBytes, 0);
                    cipher.DoFinal(plainBytes, retLen);

                    sR = Encoding.UTF8.GetString(plainBytes).TrimEnd("\r\n\0".ToCharArray());
                }
                catch (Exception ex)
                {
                    s_logger.Error("Error encountered decrypting cookie value", ex);
                }

                return sR;
            }

            public static void prepare(byte[] encryptedData, out byte[] nonce, out byte[] ciphertextTag)
            {
                nonce = new byte[12];
                ciphertextTag = new byte[encryptedData.Length - 3 - nonce.Length];

                System.Array.Copy(encryptedData, 3, nonce, 0, nonce.Length);
                System.Array.Copy(encryptedData, 3 + nonce.Length, ciphertextTag, 0, ciphertextTag.Length);
            }
        }
    }

     public static class ChromiumDbDateTimeExtensions
    {
        //1601-01-01T00:00:00Z
        private static DateTimeOffset ProlepticGregorianEpoch = new DateTimeOffset(1601, 1, 1, 0, 0, 0, TimeSpan.Zero);

        /// <summary>
        /// Convert a Chromium DB Proleptic Gregorian Time Stamp to Unix Time        
        /// <para>
        /// Timestamps
        //     The expires_utc and creation_utc fields contain timestamps given as integer numbers of microseconds elapsed since midnight 01-Jan-1601 UTC in the proleptic calendar.
        //     The Unix epoch is 11644473600 seconds after this moment.
        /// </para>
        /// <see cref="https://gist.github.com/creachadair/937179894a24571ce9860e2475a2d2ec#timestamps"/>
        /// </summary>
        /// <param name="prolepticGregorianBasedTimeInMicroseconds "></param>
        /// <returns></returns>
        public static long ChromiumDbTimeToUnixTime(this long prolepticGregorianEpochBasedTimeInMicroseconds)
        {
            var unixTimeSeconds = (prolepticGregorianEpochBasedTimeInMicroseconds / 1000000) + ProlepticGregorianEpoch.ToUnixTimeSeconds();
            return unixTimeSeconds;
        }      
    }

}
