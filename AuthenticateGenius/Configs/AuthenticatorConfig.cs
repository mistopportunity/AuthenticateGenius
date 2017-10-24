using System;
using System.Text;

namespace AuthenticateGenius {
	public struct AuthenticatorConfig {
		public GeniusStorage UserStorage {
			internal get; set;
		}
		public InputBlocker InputBlocker {
			internal get; set;
		}
		public TimeSpan? TokenExpiration {
			internal get; set;
		}
	}
}
