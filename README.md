# AuthenticateGenius
A lightweight user authentication system built on top of a runtime redundant database (Which means manually deleted data persists until the runtime is over unless internally accessed before the runtime is over.)

**Todo/unfinished components**:
- Finish InputBlocker
- implement AccessToken client linking
- more secure username storage

```c#
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
```
