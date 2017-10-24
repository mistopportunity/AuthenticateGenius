# AuthenticateGenius
A lightweight user authentication system built on top of a runtime redundant database (which means manually deleted data persists until the runtime is over unless internally accessed before the runtime is over.)

**Todo/unfinished components**:
- Implement AccessToken client linking
- Prevent servideside username swap exploits
- Token overtaken client callback

```c#
var authenticator = new Authenticator(new AuthenticatorConfig() {

	InputBlocker=new InputBlocker(new InputBlockerConfig() {

		PasswordConstraint=new LengthConstraint(4,64),
		UsernameConstraint=new LengthConstraint(1,24)
	}),

	TokenExpiration=TimeSpan.FromHours(0.5),

	UserStorage=new GeniusStorage(
		directory: "users",
		hashLength: 6
	)

});
```
