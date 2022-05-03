/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 *  The ontology is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  The ontology is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package com.github.ontid.common;

import com.alibaba.fastjson.JSONObject;

import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * Byte Handle Helper
 */
public class Helper {

    public static byte[] reverse(byte[] v) {
        byte[] result = new byte[v.length];
        for (int i = 0; i < v.length; i++) {
            result[i] = v[v.length - i - 1];
        }
        return result;
    }

    public static byte[] hexToBytes(String value) {
        if (value == null || value.length() == 0) {
            return new byte[0];
        }
        if (value.length() % 2 == 1) {
            throw new IllegalArgumentException();
        }
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    public static String toHexString(byte[] value) {
        StringBuilder sb = new StringBuilder();
        for (byte b : value) {
            int v = Byte.toUnsignedInt(b);
            sb.append(Integer.toHexString(v >>> 4));
            sb.append(Integer.toHexString(v & 0x0f));
        }
        return sb.toString();
    }

    public static String toString(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry e : map.entrySet()) {
            sb.append("\n").append(e.getKey() + ": " + e.getValue());
        }
        return sb.toString();
    }

    public static boolean checkURI(String uri) {
        if (uri == null || "".equals(uri)) {
            return true;
        }
        try {
            URI.create(uri);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean checkIssuerValid(Object issuer) {
        String ty = issuer.getClass().getTypeName();
        boolean isJavaC = isJavaClass(issuer.getClass());
        if (!ty.equals("java.lang.String") && isJavaC) {
            return false;
        }
        if (ty.equals("java.lang.String")) {
            return checkURI((String) issuer);
        } else if (!isJavaC) {
            return checkStructUri(issuer);
        } else {
            return false;
        }
    }

    public static boolean checkCredentialSubject(Object credentialSubject) {
        String ty = credentialSubject.getClass().getTypeName();
        boolean isJavaC = isJavaClass(credentialSubject.getClass());
        if (!ty.equals("java.lang.List") && isJavaC) {
            return false;
        }
        if (ty.equals("java.lang.List")) {
            for (Object obj : (List) credentialSubject) {
                if (!checkStructUri(obj)) {
                    return false;
                }
            }
            return true;
        } else if (!isJavaC) {
            return checkStructUri(credentialSubject);
        } else {
            return false;
        }
    }

    public static boolean checkStructUri(Object credentialSubject) {
        boolean isJavaC = isJavaClass(credentialSubject.getClass());
        if (isJavaC) {
            return false;
        }
        try {
            String obj = JSONObject.toJSONString(credentialSubject);
            JSONObject objJ = JSONObject.parseObject(obj);
            Object id = objJ.get("id");
            if (id == null) {
                return false;
            }
            if (!id.getClass().getTypeName().equals("java.lang.String")) {
                return false;
            }
            return checkURI((String) id);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static boolean isJavaClass(Class<?> clz) {
        return clz != null && clz.getClassLoader() == null;
    }
}
