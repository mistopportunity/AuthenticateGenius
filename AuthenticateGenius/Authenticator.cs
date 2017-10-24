using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace AuthenticateGenius {
	public sealed class Authenticator {
		private readonly Dictionary<string,AccessToken> tokenPool =
			new Dictionary<string,AccessToken>();
		private readonly GeniusStorage userStorage;
		private readonly InputBlocker inputBlocker;
		internal readonly TimeSpan tokenExpiration;
		private const int SaltSize = 16;
		private const int SaltLength = SaltSize*2;
		private const int HashLength = 64;
		public Authenticator() {
			userStorage=new GeniusStorage();
			inputBlocker=new InputBlocker();
			tokenExpiration=TimeSpan.FromDays(1);
		}
		public Authenticator(AuthenticatorConfig config) {

			userStorage = config.UserStorage??new GeniusStorage();

			inputBlocker=inputBlocker = config.InputBlocker??new InputBlocker();

			tokenExpiration=tokenExpiration=(config.TokenExpiration.HasValue ?
				(TimeSpan)config.TokenExpiration:TimeSpan.FromDays(1));

		}
		public bool UserExists(string username) {
			return inputBlocker.CheckUsername(username)
				== InputResponse.Valid &&
				userStorage.Get(username)!=null;
		}
		private bool VerifyPassword(string username,string password) {
			string authorizationData = userStorage.Get(username);
			return string.Equals(
				authorizationData.Substring(SaltLength,HashLength),
				GetHash(password,authorizationData.Substring(0,SaltLength))
			);
		}
		public CreationResponse CreateUser(
			string username,
			string password,
			out AccessToken accessToken
		) {
			accessToken=null;
			switch(inputBlocker.CheckUsername(username)) {
				case InputResponse.TooLong:
					return CreationResponse.UsernameTooLong;
				case InputResponse.TooShort:
					return CreationResponse.UsernameTooShort;
				case InputResponse.ContainsInvalidCharacters:
					return CreationResponse.UsernameContainsInvalidCharacters;
			}
			if(userStorage.Get(username)!=null) {
				return CreationResponse.UserAlreadyExists;
			} else {
				switch(inputBlocker.CheckPassword(password)) {
					case InputResponse.TooLong:
						return CreationResponse.PasswordTooLong;
					case InputResponse.TooShort:
						return CreationResponse.PasswordTooShort;
					case InputResponse.ContainsInvalidCharacters:
						return CreationResponse.PasswordContainsInvalidCharacters;
				}
				string salt = GetSalt();
				userStorage.Set(username,salt+GetHash(password,salt));
				accessToken=new AccessToken(username,this);
				tokenPool.Add(username,accessToken);
				return CreationResponse.Success;
			}
		}
		public SignInResponse SignIn(
			string username,
			string password,
			out AccessToken accessToken
		) {
			accessToken=null;
			switch(inputBlocker.CheckUsername(username)) {
				case InputResponse.Valid:
					break;
				default:
					accessToken=null;
					return SignInResponse.UserDoesNotExist;
			}
			if(userStorage.Get(username)!=null) {
				if(inputBlocker.CheckPassword(password)==InputResponse.Valid
					&&VerifyPassword(username,password)) {
					accessToken=new AccessToken(username,this);
					if(tokenPool.ContainsKey(username)) {
						tokenPool[username].Deauthorize();
						tokenPool[username]=accessToken;
					} else {
						tokenPool.Add(username,accessToken);
					}	
					return SignInResponse.Success;
				} else {
					return SignInResponse.InvalidPassword;
				}
			} else {
				return SignInResponse.UserDoesNotExist;
			}
		}
		public ActionResponse ChangePassword(AccessToken accessToken,string password) {
			if(
				accessToken.Authorized&&
				inputBlocker.CheckPassword(password)==InputResponse.Valid
				
			) {
				if(VerifyPassword(accessToken.Username,password)) {
					string salt = GetSalt();
					userStorage.Set(accessToken.Username,salt+GetHash(password,salt));
					return ActionResponse.Success;
				} else {
					return ActionResponse.Unauthorized;
				}
			} else {
				return ActionResponse.Unauthorized;
			}
		}
		public ActionResponse DeleteUser(AccessToken accessToken,string password) {
			if(accessToken.Authorized&&
				inputBlocker.CheckPassword(password)==InputResponse.Valid&&
				VerifyPassword(accessToken.Username,password)
			) {
				accessToken.Deauthorize();
				tokenPool.Remove(accessToken.Username);
				userStorage.Delete(accessToken.Username);
				return ActionResponse.Success;
			}
			return ActionResponse.Unauthorized;
		}
		public ActionResponse SignOut(AccessToken accessToken) {
			if(accessToken.Persists) {
				accessToken.Deauthorize();
				tokenPool.Remove(accessToken.Username);
				return ActionResponse.Success;
			} else {
				return ActionResponse.Unauthorized;
			}
		}
		public ActionResponse RefreshToken(AccessToken accessToken,string password) {
			if(
				accessToken.Persists&&
				inputBlocker.CheckPassword(password)==InputResponse.Valid&&
				VerifyPassword(accessToken.Username,password)
			) {
				accessToken.Refresh();
				return ActionResponse.Success;
			} else {
				return ActionResponse.Unauthorized;
			}
		}
		private string GetHash(string password,string salt) {
			using(SHA256 hasher = SHA256.Create()) {
				return BitConverter.ToString(hasher.ComputeHash(
					Encoding.Unicode.GetBytes(password+salt)
				)).
					Replace("-","").
					ToLowerInvariant();
			}
		}
		private string GetSalt() {
			using(var salter = RandomNumberGenerator.Create()) {
				byte[] bytes = new byte[SaltSize];
				salter.GetBytes(bytes);
				return BitConverter.ToString(bytes).
					Replace("-","").
					ToLowerInvariant();
			}
		}
	}
}
