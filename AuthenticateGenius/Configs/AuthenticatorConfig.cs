using System;
using System.Text;

namespace AuthenticateGenius {
	public struct AuthenticatorConfig {
		public GeniusStorage Storage {
			internal get; set;
		}
		public InputBlocker InputBlocker {
			internal get; set;
		}
		public TimeSpan? Expiration {
			internal get; set;
		}
		public Encoding Encoding {
			internal get; set;
		}
	}
}
