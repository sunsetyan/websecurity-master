/**
 * 
 */
package com.sunrise22.websecurity;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Vector;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.Part;

import com.sunrise22.websecurity.config.SecurityConstant;
import com.sunrise22.websecurity.util.XssUtil;
import com.sunrise22.websecurity.util.XssUtil.XssFilterTypeEnum;

/**
 * @author lsheng
 * 由于各种形式的数据结构表征的请求都有可能被用到，这里要将这些方法都过滤一遍。
 *
 */
public class SecurityHttpServletRequest extends HttpServletRequestWrapper {

	public SecurityHttpServletRequest(HttpServletRequest request) {
		super(request);
	}
	
	@Override
	public String getParameter(String name) {
		// TODO 这里的策略是通用的
		// 过滤策略指定为ESCAPE。
		return XssUtil.xssFilter(super.getParameter(
				XssUtil.xssFilter(name, XssFilterTypeEnum.DELETE.getValue())), null);
	}
	
	@Override
	public Map<String, String[]> getParameterMap() {
		Map<String, String[]> paramsMap = super.getParameterMap();
		if (paramsMap == null || paramsMap.isEmpty()) {
			return paramsMap;
		} 
		Map<String, String[]> result = new HashMap<String, String[]>();
		// 常用的map遍历。
		Iterator<Entry<String, String[]>> iter = paramsMap.entrySet().iterator();
		while (iter.hasNext()) {
			Entry<String, String[]> entry = iter.next();
			result.put(
					(XssUtil.xssFilter(entry.getKey(),
							XssFilterTypeEnum.DELETE.getValue())),
					filterList(entry.getValue()));
		}
		return result;
	}
	
	@Override
	public Enumeration<String> getParameterNames() {
		Enumeration<String> enums = super.getParameterNames();
		Vector<String> vec = new Vector<String>();
		while(enums.hasMoreElements()) {
			String value = enums.nextElement();
			vec.add(XssUtil.xssFilter(value, null));
		}
		return vec.elements();
	}
	
	@Override
	public String[] getParameterValues(String name) {
		return filterList(super.getParameterValues(name));
	}

	/** 对于单一的元素都算在这了过滤一次 */
	private String[] filterList(String[] values) {
		if (values == null || values.length == 0)
			return values;
		List<String> result = new ArrayList<String>();
		for (String val : values)
			result.add(XssUtil.xssFilter(val, null));
		return result.toArray(new String[result.size()]);
	}
	
	/** 每个part都以whiteFilePostFixList中的策略过滤一次, 属于其中任何一种白名单则添加。*/
	@Override
	public Collection<Part> getParts() throws IOException, ServletException {
		Collection<Part> parts = super.getParts();
		if (parts == null || parts.isEmpty() ||
				SecurityConstant.whitefilePostFixList == null ||
				SecurityConstant.whitefilePostFixList.isEmpty()) {
			return parts;
		}
		List<Part> result = new ArrayList<Part>();
		for (Part part : parts) {
			for (String extension : SecurityConstant.whitefilePostFixList) {
				if (part.getName().toUpperCase().endsWith(extension)) {
					result.add(part);
				}
			}
		}
		return result;
	}
	
	@Override
	public Part getPart(String name) throws IOException, ServletException {
		Part part = super.getPart(name);
		if (SecurityConstant.whitefilePostFixList == null
				|| SecurityConstant.whitefilePostFixList.isEmpty())
			return part;
		String value = part.getHeader("content-disposition");
		// 请求的最后一个参数是文件名。
		String filename = value.substring(value.lastIndexOf("=") + 2, value.length() - 1);
		for (String extension : SecurityConstant.whitefilePostFixList) {
			if (filename.toUpperCase().endsWith(extension.toUpperCase())) 
				return part;
		}
		// TODO 如果return null 需要进行判别
		return null;
	}

}
