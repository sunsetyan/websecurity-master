/**
 * 
 */
package com.sunrise22.websecurity.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 介绍 ：<a href=http://baike.baidu.com/view/50325.htm>xss</a>
 * @author lsheng
 *
 */
public class XssUtil {
	
	/** 一般脚本的标记 */
	private static String xssType = "<script[^>]*?>.*?</script>";
	
	private static Pattern xssPattern = Pattern.compile(xssType);
	
	/** 根据设置的filtertype来决定策略
	 * NO 不处理
	 * DELETE 全部删掉脚本
	 * ESCAPE 略过，将脚本的执行能力去掉，但是保留脚本内容。
	 * 如果指定filtertype为未知的，则默认采取ESCAPE策略。
	 */
	public static String xssFilter(String input, String filterType) {
		if (input == null || input.isEmpty())
			return input;
		if (filterType == null || !XssFilterTypeEnum.checkValid(filterType)) {
			filterType = XssFilterTypeEnum.ESCAPE.getValue();
		}
		/** 只要注入了脚本就认为是不合法的 */
		if (filterType.equals(XssFilterTypeEnum.ESCAPE.getValue())) {
			Matcher machter = xssPattern.matcher(input);
			if (machter.find())
				return machter.group().replace("<", "&lt;").replace(">", "&gt;");
		}
		if (filterType.equals(XssFilterTypeEnum.DELETE.getValue())) {
			return input.replaceAll(xssType, "");
		}
		return input;
	}
	
	/**
	 * 过滤类型
	 */
	public static enum XssFilterTypeEnum {
		ESCAPE("escape"), NO("no"), DELETE("delete");

		private String value;

		private XssFilterTypeEnum(String type) {
			this.value = type;
		}

		public String getValue() {
			return this.value;
		}

		public static boolean checkValid(String type) {
			if (type == null)
				return false;
			return (ESCAPE.getValue().equals(type)|| 
					NO.getValue().equals(type) || DELETE.getValue().equals(type));
		}
	}

}
