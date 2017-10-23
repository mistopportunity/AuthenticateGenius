using System;
using AuthenticateGenius;
using System.Text;
using System.Collections.Generic;

namespace AuthenticateGeniusTest {
	class Program {
		static void Main() {

			var tokens = new List<AccessToken>();

			var authenticator = new Authenticator(new AuthenticatorConfig() {

				Encoding=Encoding.Unicode,
				Expiration=TimeSpan.FromMinutes(30),
				Storage=new GeniusStorage("users"),

				InputBlocker=new InputBlocker(new InputBlockerConfig() {
					Password=InputWhitelist.Default,
					Username=InputWhitelist.Default,
					UsernameConstraint=new LengthConstraint(4,18),
					PasswordConstraint=new LengthConstraint(8,128),
				}),

			});

			Start:
			Console.WriteLine("Yo, sign in or make an account.");
			Console.Write("Username: ");
			string username = Console.ReadLine();
			Console.Write("Password: ");
			string password = Console.ReadLine();

			if(authenticator.UserExists(username)) {

				switch(authenticator.SignIn(
					username,
					password,
					out AccessToken token
				)) {
					case SignInResponse.Success:
						Console.WriteLine("Welcome back to.. a fun place.");
						tokens.Add(token);
						break;
					case SignInResponse.InvalidPassword:
						Console.WriteLine("Invalid password. You suck.");
						break;
				}
			} else {
				switch(authenticator.CreateUser(
					username,
					password,
					out AccessToken token
				)) {
					case CreationResponse.Success:
						Console.WriteLine("Woo-hoo! Welcome to.. a fun place.");
						tokens.Add(token);
						break;
					case CreationResponse.PasswordContainsInvalidCharacters:
					case CreationResponse.PasswordTooShort:
					case CreationResponse.PasswordTooLong:
						Console.WriteLine("Your password offends me. Start over.");
						break;
					case CreationResponse.UsernameContainsInvalidCharacters:
					case CreationResponse.UsernameTooLong:
					case CreationResponse.UsernameTooShort:
						Console.WriteLine("We don't like yer username! Piss off!");
						break;
				}
			}

			Console.ReadKey(true);
			goto Start;
		}
	}
}
