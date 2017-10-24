using System;
using AuthenticateGenius;
using System.Text;
using System.Collections.Generic;

namespace AuthenticateGeniusTest {
	internal static class Program {
		private static void Main() {


			List<AccessToken> tokens = new List<AccessToken>();

			var authenticator = new Authenticator(new AuthenticatorConfig() {

				InputBlocker=new InputBlocker(new InputBlockerConfig() {

					PasswordConstraint=new LengthConstraint(4,64),
					UsernameConstraint=new LengthConstraint(1,24)
				}),

				TokenExpiration=TimeSpan.FromHours(0.5),

				UserStorage=new GeniusStorage(
					directory: "users",
					hashLength: 8
				)

			});

			Console.Write("Bring the pain");
			Console.ReadKey(true);
			Console.WriteLine();

			for(int i = 0;i<100000;i+=1) {
				var user = authenticator.CreateUser(i.ToString(),"password",out AccessToken token);
				tokens.Add(token);
			}

			Console.Write("Yikes. That was scary");
			Console.ReadKey(true);
			Console.WriteLine();

			foreach(AccessToken token in tokens) {
				authenticator.DeleteUser(token,"password");
			}
			tokens.Clear();

		}
	}
}
