namespace AuthenticateGenius {
	public struct InputBlockerConfig {
		public char[] UsernameWhitelist {
			internal get; set;
		}
		public char[] PasswordWhitelist {
			internal get; set;
		}
		public LengthConstraint? UsernameConstraint {
			internal get; set;
		}
		public LengthConstraint? PasswordConstraint {
			internal get;set;
		}
	}
}
