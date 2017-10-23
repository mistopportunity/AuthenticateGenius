using System;

public sealed class AccessToken {
	internal AccessToken(string username) {
		this.username=username;
		time=DateTime.Now;
	}
	private bool persists = true;
	private readonly string username;
	private DateTime time;
	public string Username {
		get {
			return username;
		}
	}
	internal DateTime Time {
		get {
			return time;
		}
		set {
			time=value;
		}
	}
	public bool Persists {
		get {
			return persists;
		}
		internal set {
			persists=value;
		}
	}
}
