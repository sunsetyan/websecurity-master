package com.sunrise22.websecurity;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.sunrise22.websecurity.config.SecurityConstant;

/**
 * 默认
 */
public class DefaultBseSecurityFilter implements Filter {

	/** 不同的过滤器使用不同的策略，但是采用同一的接口来调用 */
	private List<SecurityFilter> securityFilters = new ArrayList<SecurityFilter>();

	@Override
	public void destroy() {
		// TODO 这里不对日志等内容进行处理，亦不采取安全性之外的策略。
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain filterChain) throws IOException, ServletException {
		if (request instanceof HttpServletRequest
				&& response instanceof HttpServletResponse) {
			HttpServletRequest httpReq = (HttpServletRequest) request;
			HttpServletResponse httpRes = (HttpServletResponse) response;
			// for (int i = 0; i < securityFilters.size(); i++) {
			// securityFilters.get(i).doFilterInvoke(httpReq, httpRes);
			// } // TODO 编译器可能可以告诉哪种写法比较好
			for (SecurityFilter security : securityFilters) {
				security.doFilterInvoke(httpReq, httpRes);
			}
			filterChain.doFilter(new SecurityHttpServletRequest(httpReq),
					new SecurityHttpServletResponse(httpRes));
			return;
		}
		// 如果不是HTTPServletRequest请求，则只需要经过另外的安全策略
		filterChain.doFilter(request, response);
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// 加载不同的配置文件中的内容
		initCookieWhiteList(filterConfig);
		initWhitefilePostFixList(filterConfig);
		initOnlyPostUrlList(filterConfig);
		try {
			initSecurityFilterList(filterConfig);
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (InstantiationException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		}
	}

	/** Cookie白名单，加载 */
	public void initCookieWhiteList(FilterConfig config) {
		// 这个在web.xml当中配置了,
		String list = config.getInitParameter("cookieWhiteList");
		if (list == null || list.length() == 0)
			return; // TODO 没有任何白名单。 要记录错误日志
		String[] cookieList = list.split(",");
		// 恩 自己写的应该不如编译器可能优化的公共类库
		SecurityConstant.cookieWhiteList.addAll(Arrays.asList(cookieList));
	}

	/** 文件上传后缀白名单验证 ，加载 */
	public void initWhitefilePostFixList(FilterConfig config) {
		// 这个在web.xml当中配置了,
		String list = config.getInitParameter("whitefilePostFixList");
		if (list == null || list.length() == 0)
			return; // TODO 没有任何白名单。 要记录错误日志
		String[] cookieList = list.split(",");
		SecurityConstant.whitefilePostFixList.addAll(Arrays.asList(cookieList));
	}

	/** 对只能post的url请求进行过滤 ，加载 */
	public void initOnlyPostUrlList(FilterConfig config) {
		// 这个在web.xml当中配置了,
		String list = config.getInitParameter("onlyPostUrlList");
		if (list == null || list.length() == 0)
			return;
		String[] onlyPostUrlList = list.split(",");
		SecurityConstant.onlyPostUrlList.addAll(Arrays.asList(onlyPostUrlList));
	}

	/** 加载 配置重定向白名单url参数 这个一般起始不调用 而有其他地方来控制。*/
	public void initRedirectWhiteList(FilterConfig config) {
		// 这个在web.xml当中配置了,
		String list = config.getInitParameter("redirectWhiteList");
		if (list == null || list.length() == 0)
			return;
		String[] redirectWhiteList = list.split(",");
		List<Pattern> patterns = new ArrayList<Pattern>();
		for (String str : redirectWhiteList) {
			patterns.add(Pattern.compile(str));
		}
		SecurityConstant.redirectLocationWhiteList.addAll(patterns);
	}
	
	private void initSecurityFilterList(FilterConfig config)
			throws ClassNotFoundException, InstantiationException,
			IllegalAccessException {
		// TODO 这里抛出的异常都应作为日志处理。 
		String securityFilterS = config.getInitParameter("securityFilterList");
		if (securityFilterS == null || securityFilterS.isEmpty())
			return; 	// 什么策略都没做.
		String[] filterList = securityFilterS.split(",");
		for (String filter : filterList) {
			// 根据加载出来的过滤器名称找到处理类
			@SuppressWarnings("rawtypes")
			Class/*<?>*/ securityFilter = Class.forName(filter);
			SecurityFilter securityFilterInstance = (SecurityFilter) securityFilter.newInstance();
			// 这一步才是最后加载
			securityFilters.add(securityFilterInstance);
		}
	}

}
