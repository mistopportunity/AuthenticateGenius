namespace AuthenticateGenius {
	public struct LengthConstraint {
		public int Minimum;
		public int Maximum;
		public LengthConstraint(int minimum,int maximum) {
			Minimum=minimum;
			Maximum=maximum;
		}
		internal static LengthConstraint Default =>
			new LengthConstraint(int.MinValue,int.MaxValue);
	}
}
