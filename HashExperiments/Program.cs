using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HashExperiments
{
    using System.Diagnostics;
    using System.Security.Cryptography;
    using ServiceStack.Text;

    class Program
    {
        static void Main(string[] args)
        {
            var mm3 = new Murmur3();
            var md5 = new MD5CryptoServiceProvider();
            var sha1 = new SHA1CryptoServiceProvider();
            var sha256 = new SHA256CryptoServiceProvider();
            var sha256Managed = new SHA256Managed();
            var sha256Cng = new SHA256Cng();
            var sha512 = new SHA512CryptoServiceProvider();
            var sha512Managed = new SHA512Managed();
            var rnd = new Random();
            var keepGoing = "y";
            var sWatch = new Stopwatch();
            while (keepGoing == "y")
            {
                var times = new List<TimesTaken>();
                var numberGenerated = rnd.Next(minValue: Int32.MinValue, maxValue: Int32.MaxValue);

                var usr = new Admin();
                usr.EmailAddress = "Brian@Hallmanac.com";
                usr.FirstName = "Brian";
                usr.LastName = "Hall";
                usr.NameOfEmployeeMinion = "Minion";
                usr.RandomNumber = numberGenerated;
                usr.UserAddress = new Address
                {City = "Orlando", State = "FL", StreetName = "Glen ST", StreetNumber = rnd.Next(0, 9999), ZipCode = rnd.Next(0, 99999)};
                usr.UserId = Guid.NewGuid();

                sWatch.Restart();
                var serializedString = usr.UserAddress.SerializeToString().ToUtf8Bytes();
                sWatch.Stop();
                var serializedTime = sWatch.Elapsed;
                
                // MurMur3
                sWatch.Restart();
                var theHash = mm3.ComputeHash(serializedString);
                var encodedHash = HashBytesToHexString(theHash);
                sWatch.Stop();
                times.Add(new TimesTaken {HashType = "MurMur3", Time = sWatch.Elapsed});
                Console.WriteLine("The MurMur3 hashed value is: {0}", encodedHash);
                Console.WriteLine("The length of the hashed value is {0}", encodedHash.Length);
                Console.WriteLine("The time taken for MurMur3 was {0}.\n", sWatch.Elapsed);

                // md5
                sWatch.Restart();
                var md5Hash = md5.ComputeHash(serializedString);
                var encodedMd5Hash = HashBytesToHexString(md5Hash);
                sWatch.Stop();
                times.Add(new TimesTaken{HashType = "MD5", Time = sWatch.Elapsed});
                Console.WriteLine("The MD5 hashed value is: {0}", encodedMd5Hash);
                Console.WriteLine("The length of the Md5 hash value is {0}", encodedMd5Hash.Length);
                Console.WriteLine("The length of time taken for Md5 was {0}.\n", sWatch.Elapsed);

                // SHA1
                sWatch.Restart();
                var sha1Hash = sha1.ComputeHash(serializedString);
                var encodedSha1Hash = HashBytesToHexString(sha1Hash);
                sWatch.Stop();
                times.Add(new TimesTaken{HashType = "Sha1", Time = sWatch.Elapsed});
                Console.WriteLine("The Sha1 hashed value is {0}", encodedSha1Hash);
                Console.WriteLine("The length of the hashed value is {0}", encodedSha1Hash.Length);
                Console.WriteLine("The time taken for Sha1 was {0}\n", sWatch.Elapsed);

                // SHA256
                sWatch.Restart();
                var sha256Hash = sha256.ComputeHash(serializedString);
                var encodedSha256Hash = HashBytesToHexString(sha256Hash);
                sWatch.Stop();
                times.Add(new TimesTaken{HashType = "SHA256", Time = sWatch.Elapsed});
                Console.WriteLine("The Sha256 hashed value is {0}", encodedSha256Hash);
                Console.WriteLine("The length of the hashed value is {0}", encodedSha256Hash.Length);
                Console.WriteLine("The time taken for SHA256 was {0}\n", sWatch.Elapsed);

                // SHA256-Managed
                sWatch.Restart();
                var sha256ManagedHash = sha256Managed.ComputeHash(serializedString);
                var encodedSha256ManagedHash = HashBytesToHexString(sha256ManagedHash);
                sWatch.Stop();
                times.Add(new TimesTaken { HashType = "SHA256-Managed", Time = sWatch.Elapsed });
                Console.WriteLine("The Sha256-Managed hashed value is {0}", encodedSha256ManagedHash);
                Console.WriteLine("The length of the hashed value is {0}", encodedSha256ManagedHash.Length);
                Console.WriteLine("The time taken for SHA256-Managed was {0}\n", sWatch.Elapsed);

                // SHA256-CNG
                sWatch.Restart();
                var sha256CngHash = sha256Cng.ComputeHash(serializedString);
                var encodedSha256CngHash = HashBytesToHexString(sha256CngHash);
                sWatch.Stop();
                times.Add(new TimesTaken { HashType = "SHA256-CNG", Time = sWatch.Elapsed });
                Console.WriteLine("The Sha256-CNG hashed value is {0}", encodedSha256CngHash);
                Console.WriteLine("The length of the hashed value is {0}", encodedSha256CngHash.Length);
                Console.WriteLine("The time taken for SHA256-CNG was {0}\n", sWatch.Elapsed);

                // SHA512
                sWatch.Restart();
                var sha512Hash = sha512.ComputeHash(serializedString);
                var encodedSha512Hash = HashBytesToHexString(sha512Hash);
                sWatch.Stop();
                times.Add(new TimesTaken { HashType = "SHA512", Time = sWatch.Elapsed });
                Console.WriteLine("The Sha512 hashed value is {0}", encodedSha512Hash);
                Console.WriteLine("The length of the hashed value is {0}", encodedSha512Hash.Length);
                Console.WriteLine("The time taken for SHA512 was {0}\n", sWatch.Elapsed);

                // SHA512-Managed
                sWatch.Restart();
                var sha512ManagedHash = sha512Managed.ComputeHash(serializedString);
                var encodedSha512ManagedHash = HashBytesToHexString(sha512ManagedHash);
                sWatch.Stop();
                times.Add(new TimesTaken { HashType = "SHA512-Managed", Time = sWatch.Elapsed });
                Console.WriteLine("The Sha512-Managed hashed value is {0}", encodedSha512ManagedHash);
                Console.WriteLine("The length of the hashed value is {0}", encodedSha512ManagedHash.Length);
                Console.WriteLine("The time taken for SHA512-Managed was {0}\n", sWatch.Elapsed);

                Console.WriteLine("The value serialized and hashed was: \n{0}", usr.UserAddress.SerializeAndFormat());

                var fastestTime = times.OrderBy(t => t.Time).First();
                Console.WriteLine("\nThe fastest time was {0}\n", fastestTime.HashType);
                Console.WriteLine("The serialization time was {0}\n", serializedTime);

                times = times.OrderBy(t => t.Time).ToList();
                times.ForEach(t => Console.WriteLine("{0}: {1}", t.HashType, t.Time));
                
                Console.WriteLine("\nAgain? [y/n]\n");
                keepGoing = Console.ReadLine().ToLower();
            }
        }

        private static string HashBytesToHexString(byte[] sha256Hash)
        {
            var sb = new StringBuilder();
            foreach(var b in sha256Hash)
            {
                sb.Append(b.ToString("X2"));
            }
            return sb.ToString();
        }
    }

    public struct TimesTaken
    {
        public TimeSpan Time { get; set; }
        public string HashType { get; set; }
    }
}
