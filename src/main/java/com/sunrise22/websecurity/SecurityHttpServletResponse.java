/**
 * 
 */
package com.sunrise22.websecurity;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import com.sunrise22.websecurity.config.SecurityConstant;
import com.sunrise22.websecurity.util.ResponseHeaderSecurityCheck;

/**
 * @author lsheng
 *
 */
public class SecurityHttpServletResponse extends HttpServletResponseWrapper {
	
	public SecurityHttpServletResponse(HttpServletResponse response) {
		super(response);
	}

	/** 4kb是常用大小 磁盘的簇， windows文件碎片 ..*/
	private static final int MAX_COOKIE_SIZE = 4 * 1024;
	
	private int length = 0;
	
	@Override
	public void addCookie(Cookie cookie) {
		if (length + cookie.getValue().length() > MAX_COOKIE_SIZE) 
			return;
		if (!isInWhiteList(cookie))
			throw new RuntimeException("cookie : " + cookie.getName()
					+ " is not in whitelist, not valid.");
		super.addCookie(ResponseHeaderSecurityCheck.checkCookie(cookie));
		length += cookie.getValue().length();
	}
	
	@Override
	public void setDateHeader(String name, long date) {
		super.setDateHeader(ResponseHeaderSecurityCheck.filterCLRF(name), date);
	}
	
	private boolean isInWhiteList(Cookie cookie) {
		if (cookie == null || cookie.getName() == null)
			return false;
		for (String name : SecurityConstant.cookieWhiteList) {
			if (name.equalsIgnoreCase(cookie.getName())) {
				return true;
			}
		}
		return false;
	}
	
	

}
