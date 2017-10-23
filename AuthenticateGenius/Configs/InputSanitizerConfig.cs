namespace AuthenticateGenius {
	public struct InputBlockerConfig {
		public InputWhitelist? Username {
			internal get; set;
		}
		public InputWhitelist? Password {
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
