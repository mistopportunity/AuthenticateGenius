using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace AuthenticateGenius {



	public sealed class Authenticator {



		private readonly Dictionary<string,AccessToken> tokenPool =
			new Dictionary<string,AccessToken>();

		private readonly GeniusStorage storage;
		private readonly InputBlocker inputBlocker;

		internal readonly TimeSpan expiration;
		private readonly Encoding encoding;


		private const int SaltSize = 16;
		private const int SaltLength = SaltSize*2;
		private const int HashLength = 64;

		public Authenticator() {

			storage=new GeniusStorage();
			inputBlocker=new InputBlocker();
			expiration=TimeSpan.FromDays(1);
			encoding=Encoding.Unicode;

		}

		public Authenticator(AuthenticatorConfig config) {

			storage=(config.Storage==null ?
				config.Storage : new GeniusStorage());

			inputBlocker=inputBlocker=(config.InputBlocker==null ?
				config.InputBlocker : new InputBlocker());

			expiration=expiration=(config.Expiration.HasValue ?
				(TimeSpan)config.Expiration:TimeSpan.FromDays(1));

			encoding=encoding=(config.Encoding==null ?
				config.Encoding : Encoding.Unicode);
		}
		public bool UserExists(string username) {
			return inputBlocker.CheckUsername(username)
				== InputResponse.Valid &&
				storage.Get(username)!=null;
		}

		private bool VerifyPassword(string username,string password) {
			string authorizationData = storage.Get(username);
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
			if(storage.Get(username)!=null) {
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
				storage.Set(username,salt+GetHash(password,salt));
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
			if(storage.Get(username)!=null) {
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
				inputBlocker.CheckPassword(password)==InputResponse.Valid&&
				accessToken.Authorized
			) {
				if(VerifyPassword(accessToken.Username,password)) {
					string salt = GetSalt();
					storage.Set(accessToken.Username,salt+GetHash(password,salt));
					return ActionResponse.Success;
				} else {
					return ActionResponse.Unauthorized;
				}
			} else {
				return ActionResponse.Unauthorized;
			}
		}
		public ActionResponse DeleteUser(AccessToken accessToken,string password) {
			if(
				inputBlocker.CheckPassword(password) == InputResponse.Valid&&
				accessToken.Persists
			) {
				if(!accessToken.Expired) {
					if(VerifyPassword(accessToken.Username,password)) {
						accessToken.Deauthorize();
						tokenPool.Remove(accessToken.Username);
						storage.Delete(accessToken.Username);
						return ActionResponse.Success;
					}
				}
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
				inputBlocker.CheckPassword(password)==InputResponse.Valid&&
				accessToken.Persists&&
				VerifyPassword(accessToken.Username,password)
			) {
				accessToken.Refresh();
				return ActionResponse.Success;
			} else {
				return ActionResponse.Unauthorized;
			}
		}
		private string GetHash(string password,string salt) {
			using(var hasher = SHA256.Create()) {
				byte[] bytes = hasher.ComputeHash(
					encoding.GetBytes(password+salt)
				);
				return BitConverter.ToString(bytes).
					Replace("-","").
					ToLowerInvariant();
			}
		}
		private static string GetSalt() {
			byte[] bytes = new byte[SaltSize];
			using(var salter = RandomNumberGenerator.Create()) {
				salter.GetBytes(bytes);
				return BitConverter.ToString(bytes).
					Replace("-","").
					ToLowerInvariant();
			}
		}
	}
}
