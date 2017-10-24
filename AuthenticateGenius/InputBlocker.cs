using System.Linq;
using System.Collections.Generic;

namespace AuthenticateGenius {
	public sealed class InputBlocker {
		private readonly char[] usernameWhitelist;
		private readonly char[] passwordWhitelist;
		private readonly LengthConstraint usernameConstraint;
		private readonly LengthConstraint passwordConstraint;
		private const char DefaultStart = ' ';
		private const char DefaultEnd = '~';
		public char[] GetCharRange(char start,char end) {
			IEnumerable<char> GetDefaults() {
				for(char i = start;i<end;i++) {
					yield return i;
				}
			}
			return GetDefaults().ToArray();
		}
		public InputBlocker() {
			usernameWhitelist=GetCharRange(DefaultStart,DefaultEnd);
			passwordWhitelist=usernameWhitelist;
			usernameConstraint=LengthConstraint.Default;
			passwordConstraint=LengthConstraint.Default;
		}
		public InputBlocker(InputBlockerConfig config) {
			if(config.UsernameWhitelist != null) {
				usernameWhitelist=config.UsernameWhitelist;
			} else {
				usernameWhitelist=GetCharRange(DefaultStart,DefaultEnd);
			}
			if(config.PasswordWhitelist!=null) {
				usernameWhitelist=config.PasswordWhitelist;
			} else if(usernameWhitelist == null) {
				passwordWhitelist=GetCharRange(DefaultStart,DefaultEnd);
			} else {
				passwordWhitelist=usernameWhitelist;
			}
			usernameConstraint=(config.UsernameConstraint.HasValue ?
				(LengthConstraint)config.UsernameConstraint : LengthConstraint.Default);

			passwordConstraint=(config.PasswordConstraint.HasValue ?
				(LengthConstraint)config.PasswordConstraint : LengthConstraint.Default);
		}
		internal InputResponse CheckUsername(string username) {
			return Check(
				username,
				usernameWhitelist,
				usernameConstraint
			);
		}
		internal InputResponse CheckPassword(string password) {
			return Check(
				password,
				passwordWhitelist,
				passwordConstraint
			);
		}
		private static InputResponse Check(
			string value,
			char[] whitelist,
			LengthConstraint constraint
		) {
			if(value.Length<constraint.Minimum) {
				return InputResponse.TooShort;
			}
			if(value.Length>constraint.Maximum) {
				return InputResponse.TooLong;
			}
			//O(n) is surely faster and cheaper than O(1) here...
			foreach(char character in value) {
				bool matched = false;
				for(int i = 0;i<whitelist.Length;i++) {
					if(character==whitelist[i]) {
						matched=true;
						break;
					}
				}
				if(!matched) {
					return InputResponse.ContainsInvalidCharacters;
				}
			}
			return InputResponse.Valid;
		}
	}
}
