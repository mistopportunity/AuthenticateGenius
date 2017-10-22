using System;
using AuthenticateGenius;

namespace AuthenticateGeniusTest {
	class Program {
		static void Main() {
			var storage = new GeniusStorage("users");
			var authenticator = new Authenticator(storage);
			Start:
			Console.WriteLine("Yo, sign in or make an account.");
			Console.Write("Username: ");
			string username = Console.ReadLine();
			Console.Write("Password: ");
			string password = Console.ReadLine();
			if(authenticator.UserExists(username)) {
				var response = authenticator.SignInUser(username,password);
				if(response!=null) {
					Console.WriteLine($"Welcome back, {username}.");
					AllExtensivePorpoises(authenticator,response);
				} else {
					Console.WriteLine("Invalid password! AHHHH!");
				}
			} else {
				var response = authenticator.CreateUser(username,password);
				Console.WriteLine($"Hello, {username}.");
				AllExtensivePorpoises(authenticator,response);
			}
			Console.ReadKey(true);
			goto Start;
		}
		private static void AllExtensivePorpoises(Authenticator authenticator,AccessToken accessToken) {
			Console.Write("Even though you just got logged into your account, now we have to delete you for testing purposes. Sorry.\nPlease enter your password: ");
			if(authenticator.DeleteUser(accessToken.Username,Console.ReadLine())) {
				Console.WriteLine("Sorry to see you go... Until next time.");
			} else {
				Console.WriteLine("Wow, entering the wrong password on purpose to save your account? Shame, but clever.");
			}
		}
	}
}
