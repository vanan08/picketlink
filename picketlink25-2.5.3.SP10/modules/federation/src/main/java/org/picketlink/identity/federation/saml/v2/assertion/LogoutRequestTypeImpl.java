package org.picketlink.identity.federation.saml.v2.assertion;

import javax.xml.datatype.XMLGregorianCalendar;

import org.picketlink.identity.federation.saml.v2.protocol.LogoutRequestType;

public class LogoutRequestTypeImpl extends LogoutRequestType {

	private static final long serialVersionUID = 1L;
	private String timeoutMaxSecond;
	
	public LogoutRequestTypeImpl(String id, XMLGregorianCalendar instant) {
		super(id, instant);
	}

	public String getTimeoutMaxSecond() {
		return timeoutMaxSecond;
	}
	
	public void setTimeoutMaxSecond(String timeoutMaxSecond) {
		this.timeoutMaxSecond = timeoutMaxSecond;
	}
	
}
