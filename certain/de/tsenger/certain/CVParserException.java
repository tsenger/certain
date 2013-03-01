package de.tsenger.certain;

public class CVParserException extends Exception
{
    private Throwable cause;

    public CVParserException(String msg, Throwable cause) {
        super(msg);
        this.cause = cause;
    }

    public CVParserException(String msg) {
        super(msg);
    }

    @Override
	public Throwable getCause() {
        return cause;
    }
}
