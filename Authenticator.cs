using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace AuthenticateGenius {
	public sealed class Authenticator {
		private const string DefaultDirectory = "users";
		private readonly Dictionary<string,AccessToken> tokenPool = new Dictionary<string,AccessToken>();
		private readonly GeniusStorage storage;
		private readonly TimeSpan expiration;
		private readonly Encoding encoding;
		private const int SaltSize = 16;
		private const int SaltLength = SaltSize*2;
		private const int HashLength = 64;
		public Authenticator() {
			storage=new GeniusStorage(DefaultDirectory);
			expiration=TimeSpan.MaxValue;
			encoding=Encoding.Unicode;
		}
		public Authenticator(GeniusStorage storage) {
			this.storage=storage;
			expiration=TimeSpan.MaxValue;
			encoding=Encoding.Unicode;
		}
		public Authenticator(GeniusStorage storage,TimeSpan expiration) {
			this.storage=storage;
			this.expiration=expiration;
			encoding=Encoding.Unicode;
		}
		public Authenticator(GeniusStorage storage,TimeSpan expiration,Encoding encoding) {
			this.storage=storage;
			this.expiration=expiration;
			this.encoding=encoding;
		}
		//Returns null if password is invalid or user doesn't exist
		public AccessToken SignInUser(string username,string password) {
			if(VerifyPassword(username,password)) {
				AccessToken accessToken;
				if(tokenPool.ContainsKey(username)) {
					accessToken=tokenPool[username];
				} else {
					accessToken=new AccessToken(username);
					tokenPool.Add(username,accessToken);
				}
				return accessToken;
			} else {
				return null;
			}
		}
		//Returns null if user already exists
		public AccessToken CreateUser(string username,string password) {
			if(!UserExists(username)) {
				string salt = GetSalt();
				storage.Set(username,salt+GetHash(password,salt));
				AccessToken accessToken = new AccessToken(username);
				tokenPool.Add(username,accessToken);
				return accessToken;
			} else {
				return null;
			}
		}
		private bool VerifyPassword(string username,string password) {
			string value = storage.Get(username);
			if(value==null) {
				return false;
			} else {
				string salt = value.Substring(0,SaltLength);
				string hash = value.Substring(SaltLength,HashLength);
				if(hash==GetHash(password,salt)) {
					return true;
				} else {
					return false;
				}
			}
		}
		//Returns false is password is invalid or user does not exist
		public bool DeleteUser(string username,string password) {
			if(VerifyPassword(username,password)) {
				if(tokenPool.ContainsKey(username)) {
					tokenPool[username].Persists=false;
					tokenPool.Remove(username);
				}
				storage.Delete(username);
				return true;
			} else {
				return false;
			}
		}
		//Returns false is password is invalid or user does not exist
		public bool ChangePassword(string username,string password,string newPassword) {
			if(VerifyPassword(username,password)) {
				if(tokenPool.ContainsKey(username)) {
					tokenPool[username].Time=DateTime.Now;
				}
				string salt = GetSalt();
				storage.Set(username,salt+GetHash(newPassword,salt));
				return true;
			} else {
				return false;
			}
		}
		//Returns false if password is invalid or user is deleted. Cannot refresh a deauthenticated token.
		public bool RefreshToken(AccessToken accessToken,string password) {
			if(!accessToken.Persists) {
				return false;
			} else if(VerifyPassword(accessToken.Username,password)) {
				accessToken.Time=DateTime.Now;
				return true;
			} else {
				//Invalidate the token because of an incorrect password.
				DeauthenticateToken(accessToken);
				return false;
			}
		}
		//Used to sign out.
		public void DeauthenticateToken(AccessToken accessToken) {
			accessToken.Time=accessToken.Time+expiration;
		}
		//Used to see if permissions still exist or a token needs to be refreshed.
		public bool TokenValid(AccessToken accessToken) {
			return accessToken.Persists && DateTime.Now<accessToken.Time+expiration;
		}
		public bool UserExists(string username) {
			return storage.Get(username)!=null;
		}
		private string GetHash(string password,string salt) {
			using(var hasher = SHA256.Create()) {
				byte[] bytes = hasher.ComputeHash(
					encoding.GetBytes(password+salt)
				);
				return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant();
			}
		}
		private static string GetSalt() {
			byte[] bytes = new byte[SaltSize];
			using(var salter = RandomNumberGenerator.Create()) {
				salter.GetBytes(bytes);
				return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant();
			}
		}
	}
}
