using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace AuthenticateGenius {
	public sealed class GeniusStorage {
		private const string DefaultDirectory = "users";
		private const int MaxHashLength = 32;
		private readonly int hashLength;
		private readonly Dictionary<string,Dictionary<string,string>> dictionary =
			new Dictionary<string,Dictionary<string,string>>();
		private readonly string directory;
		public GeniusStorage(string directory = DefaultDirectory,int hashLength = 8) {
			void RewriteDatabase(string[] files) {
				var users = new List<Tuple<string,string>>();
				foreach(string file in files) {
					using(StreamReader streamReader = new StreamReader(file)) {
						while(streamReader.Peek()>0) {
							users.Add(new Tuple<string, string>(
								streamReader.ReadLine(),
								streamReader.ReadLine()
							));
						}
					}
				}
				foreach(var user in users) {
					var hash = GetHash(user.Item1);
					if(dictionary.ContainsKey(hash)) {
						dictionary[hash].Add(user.Item1,user.Item2);
					} else {
						dictionary.Add(hash,new Dictionary<string,string>() {
							{user.Item1,user.Item2}
						});
					}
				}
				foreach(var bucket in dictionary) {
					WriteBucket(Path.Combine(directory,bucket.Key),bucket.Value);
				}
				for(int fileIndex = 0;fileIndex<files.Length;fileIndex++) {
					File.Delete(files[fileIndex]);
				}
			}	
			this.directory=directory;
			if(hashLength>MaxHashLength) {
				this.hashLength=MaxHashLength;
			} else {
				this.hashLength=hashLength;
			}
			if(Directory.Exists(directory)) {
				string[] files = Directory.GetFiles(directory);
				if(files.Length<1) {
					return;
				}
				if(Path.GetFileName(files[0]).Length != this.hashLength) {
					RewriteDatabase(files);
					return;
				}
				foreach(string file in files) {
					var bucket = new Dictionary<string,string>();
					using(StreamReader streamReader = new StreamReader(file)) {
						while(streamReader.Peek()>0) {
							bucket.Add(
								streamReader.ReadLine(),
								streamReader.ReadLine()
							);
						}
					}
					dictionary.Add(Path.GetFileName(file),bucket);
				}
			} else {
				Directory.CreateDirectory(directory);
			}
		}
		internal void Delete(string key) {
			string hash = GetHash(key);
			if(dictionary.ContainsKey(hash)) {
				var bucket = dictionary[hash];
				var path = Path.Combine(directory,hash);
				if(bucket.Count==1) {
					dictionary.Remove(hash);
					File.Delete(path);
				} else {
					bucket.Remove(key);
					WriteBucket(path,bucket);
				}
			}
		}
		internal void WriteBucket(string path,Dictionary<string,string> bucket) {
			using(StreamWriter streamWriter = new StreamWriter(path)) {
				foreach(var key in bucket.Keys) {
					streamWriter.WriteLine($"{key}{Environment.NewLine}{bucket[key]}");
				}
			}
		}
		internal void Set(string key,string value) {
			string hash = GetHash(key);
			Dictionary<string,string> bucket;
			if(dictionary.ContainsKey(hash)) {
				bucket = dictionary[hash];
				if(bucket.ContainsKey(key)) {
					if(bucket[key]!=value) {
						bucket[key]=value;
					} else {
						return;
					}
				} else {
					bucket.Add(key,value);
				}
			} else {
				bucket = new Dictionary<string,string>() {
					{key,value}
				};
				dictionary.Add(hash,bucket);
			}
			WriteBucket(Path.Combine(directory,hash),bucket);
		}
		internal string Get(string key) {
			string hash = GetHash(key);
			if(dictionary.ContainsKey(hash)) {
				var bucket = dictionary[hash];
				if(bucket.ContainsKey(key)) {
					return bucket[key];
				} else {
					return null;
				}
			} else {
				return null;
			}
		}
		private string GetHash(string key) {
			using(MD5 hasher = MD5.Create()) {
				string hash = BitConverter.ToString(hasher.ComputeHash(
					Encoding.Unicode.GetBytes(key)
				)).Replace("-","").ToLowerInvariant();
				return hash.Substring(0,hashLength);
			}
		}
	}
}
