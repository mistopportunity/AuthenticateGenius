using System;
using System.Text;
using System.Collections.Generic;

namespace AuthenticateGenius {
	[Flags]
	public enum InputWhitelist {
		Default = 14,
		None = 0,
		Spaces = 1,
		BasicSymbols = 2,
		EnglishAlphabet = 4,
		Numbers = 8,
	}
	public sealed class InputBlocker {
		private readonly InputWhitelist username;
		private readonly InputWhitelist password;
		private readonly LengthConstraint usernameConstraint;
		private readonly LengthConstraint passwordConstraint;
		public InputBlocker() {
			username=InputWhitelist.Default;
			password=InputWhitelist.Default;
			usernameConstraint=LengthConstraint.Default;
			passwordConstraint=LengthConstraint.Default;
		}
		public InputBlocker(InputBlockerConfig config) {

			if(config.Username.HasValue) {
				InputWhitelist username = (InputWhitelist)config.Username;
				if(username.HasFlag(InputWhitelist.None)) {
					this.username=InputWhitelist.Default;
				} else
					this.username=username;
			} else {
				username=InputWhitelist.Default;
			}
			if(config.Password.HasValue) {
				InputWhitelist password= (InputWhitelist)config.Password;
				if(password.HasFlag(InputWhitelist.None)) {
					this.password=InputWhitelist.Default;
				} else
					this.password=password;
			} else {
				password=InputWhitelist.Default;
			}

			usernameConstraint=(config.UsernameConstraint.HasValue ?
				(LengthConstraint)config.UsernameConstraint: LengthConstraint.Default);

			passwordConstraint=(config.PasswordConstraint.HasValue ?
				(LengthConstraint)config.PasswordConstraint : LengthConstraint.Default);

		}

		internal InputResponse CheckUsername(string username) {
			return InputResponse.Valid;
		}

		internal InputResponse CheckPassword(string password) {
			return InputResponse.Valid;
		}

	}
}
