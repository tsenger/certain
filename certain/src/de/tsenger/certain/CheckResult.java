package de.tsenger.certain;

/**
 * Result of a check (e.g. a signature verification): its status and the text that describes it.
 * The command line tool prints the text and derives its exit code from the status.
 */
public class CheckResult {

	/** Status of a check, ordered by increasing severity. */
	public enum Status {
		/** The check passed. */
		VALID,
		/** The check could not be done, e.g. because the issuer certificate or the domain parameters are missing. */
		NOT_CHECKED,
		/** The check failed or an error occurred while checking. */
		INVALID
	}

	private final Status status;
	private final String text;

	public CheckResult(Status status, String text) {
		this.status = status;
		this.text = text;
	}

	public Status getStatus() {
		return status;
	}

	/** @return the description of the result, may span several lines */
	public String getText() {
		return text;
	}
}
