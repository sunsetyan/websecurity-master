package com.sunrise22.websecurity.util;

import java.lang.reflect.Method;

public class ClassUtil {
	
	/** 查看某个类中某个方法是否存在 */
	public static boolean checkIfExsit(Class<?> clazz, String methodName) {
		Method[] methods = clazz.getMethods();
		for (Method method : methods) {
			if (method.getName().equals(methodName))
				return true;
		}
		return false;
	}

}
