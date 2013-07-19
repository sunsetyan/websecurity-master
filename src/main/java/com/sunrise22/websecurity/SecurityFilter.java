/**
 * 
 */
package com.sunrise22.websecurity;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 安全过滤器基本接口，不同的过滤器使用不同的策略，但是采用同一的接口来调用
 * 
 * @author lsheng
 * 
 */
public interface SecurityFilter {

	/** 进行过滤操作 */
	public void doFilterInvoke(HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException;

}
