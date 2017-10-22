using System.IO;
using System.Collections.Generic;

namespace AuthenticateGenius {
	public sealed class GeniusStorage {
		private const string DefaultDirectory = "genius";
		private readonly Dictionary<string,string> dictionary;
		private readonly string directory;
		public GeniusStorage(string directory = DefaultDirectory) {
			this.directory=directory;
			dictionary=new Dictionary<string,string>();
			if(Directory.Exists(directory)) {
				foreach(string file in Directory.GetFiles(directory)) {
					string key = Path.GetFileName(file);
					string value = File.ReadAllText(file);
					dictionary.Add(key,value);
				}
			} else {
				Directory.CreateDirectory(directory);
			}
		}
		public void Delete(string key) {
			dictionary.Remove(key);
			File.Delete(Path.Combine(directory,key));
		}
		internal void Set(string key,string value) {
			if(dictionary.ContainsKey(key)) {
				if(value!=dictionary[key]) {
					dictionary[key]=value;
				} else {
					return;
				}
			} else {
				dictionary.Add(key,value);
			}
			string path = Path.Combine(directory,key);
			File.WriteAllText(path,value);
		}
		internal string Get(string key) {
			if(dictionary.ContainsKey(key)) {
				string path = Path.Combine(directory,key);
				if(!File.Exists(path)) {
					File.WriteAllText(path,dictionary[key]);
				}
				return dictionary[key];	
			} else {
				return null;
			}
		}
	}
}
