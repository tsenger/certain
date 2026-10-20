package de.tsenger.certain;

public abstract class DListParser {
	
	public abstract String getDListInfoString(boolean showDetails);

	/** Checks the content of the list against its specification; by default there is nothing to check. */
	public CheckResult check() {
		return new CheckResult(CheckResult.Status.VALID, "");
	}

}
