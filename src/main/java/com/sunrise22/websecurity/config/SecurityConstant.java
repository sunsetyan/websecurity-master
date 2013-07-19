package com.sunrise22.websecurity.config;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class SecurityConstant {
	
	/** Cookie白名单，这里只是一个简单的列表， 对于大规模访问量的网站可以做成内存缓存加数据库。*/
	public static final List<String> cookieWhiteList = new ArrayList<String>();
	
	/** 对只能post的url请求进行过滤 */
	public static final List<String> onlyPostUrlList = new ArrayList<String>();
	
	/** 文件上传后缀白名单验证 */
	public static final List<String> whitefilePostFixList = new ArrayList<String>();
	
	/** 配置重定向白名单url参数 */
	public static final List<Pattern> redirectLocationWhiteList = new ArrayList<Pattern>();
	
	public static String key;

}
