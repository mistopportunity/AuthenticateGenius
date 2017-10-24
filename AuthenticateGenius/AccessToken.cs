using System;

namespace AuthenticateGenius {
	public sealed class AccessToken {

		private readonly string username;
		private readonly Authenticator authenticator;

		internal AccessToken(string username,Authenticator authenticator) {
			this.authenticator=authenticator;
			this.username=username;
		}

		internal void Refresh() {
			Time=DateTime.Now;
		}

		internal void Deauthorize() {
			Persists=false;
		}

		public string Username {
			get {
				return username;
			}
		}

		private DateTime Time {
			get; set;
		} = DateTime.Now;

		public bool Persists {
			get; private set;
		} = true;

		public bool Expired {
			get {
				return DateTime.Now>=Time+authenticator.tokenExpiration;
			}
		}
		public bool Authorized {
			get {
				return Persists&&!Expired;
			}
		}

	}
}

