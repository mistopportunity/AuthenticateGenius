using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticateGenius {
	public enum CreationResponse {
		UserAlreadyExists,
		Success,
		UsernameTooShort,
		UsernameTooLong,
		PasswordTooShort,
		PasswordTooLong,
		UsernameContainsInvalidCharacters,
		PasswordContainsInvalidCharacters,
	}

	public enum SignInResponse {
		UserDoesNotExist,
		Success,
		InvalidPassword,
	}
	public enum ActionResponse {
		Unauthorized,
		Success,
	}
	public enum Authorization {
		Valid,
		Invalid,
		Expired,
	}
	public enum InputResponse {
		Valid,
		TooShort,
		TooLong,
		ContainsInvalidCharacters,
	}
}
