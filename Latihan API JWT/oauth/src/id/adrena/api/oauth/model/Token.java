package id.adrena.api.oauth.model;

public class Token {
	private String access;
	private String refresh;
	private String type;
	private int expiresIn; // berapa detik acces token kadaluarsa, biasanya 3600s
	
	
	public Token(String access, String refresh, String type, int expiresIn) {
		super();
		this.access = access;
		this.refresh = refresh;
		this.type = type;
		this.expiresIn = expiresIn;
	}
	public Token() {
		super();
	}
	
	
	public String getAccess() {
		return access;
	}
	/**
	 * @param access the access to set
	 */
	public void setAccess(String access) {
		this.access = access;
	}
	/**
	 * @return the refresh
	 */
	public String getRefresh() {
		return refresh;
	}
	/**
	 * @param refresh the refresh to set
	 */
	public void setRefresh(String refresh) {
		this.refresh = refresh;
	}
	/**
	 * @return the type
	 */
	public String getType() {
		return type;
	}
	/**
	 * @param type the type to set
	 */
	public void setType(String type) {
		this.type = type;
	}
	/**
	 * @return the expiresInt
	 */
	public int getExpiresIn() {
		return expiresIn;
	}
	/**
	 * @param expiresInt the expiresInt to set
	 */
	public void setExpiresIn(int expiresIn) {
		this.expiresIn = expiresIn;
	}
	
	
}
