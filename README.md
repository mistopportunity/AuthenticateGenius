# AuthenticateGenius
A *soon to be lightweight* user authentication system built on top of a messy, ram eating database structure that generates tens of thousands of files. No, this isn't a selling point. It's being reworked after very obvious reconsideration.

**Todo/unfinished components**:
- Implement AccessToken client linking
- Prevent server-side username swap exploits
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
