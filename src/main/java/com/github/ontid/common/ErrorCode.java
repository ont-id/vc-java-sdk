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

import com.alibaba.fastjson.JSON;

import java.util.HashMap;
import java.util.Map;

public class ErrorCode {
    public static String getError(int code, String msg) {
        Map map = new HashMap();
        map.put("Error", code);
        map.put("Desc", msg);
        return JSON.toJSONString(map);
    }

    //account error
    public static String UnsupportedKeyType = getError(51001, "Account Error,unsupported key type");
    public static String InvalidMessage = getError(51003, "Account Error,invalid message");
    public static String WithoutPrivate = getError(51004, "Account Error,account without private key cannot generate signature");
    public static String InvalidSM2Signature = getError(51005, "Account Error,invalid SM2 signature parameter, ID (String) excepted");
    public static String AccountInvalidInput = getError(51006, "Account Error,account invalid input");
    public static String AccountWithoutPublicKey = getError(51007, "Account Error,account without public key cannot verify signature");
    public static String UnknownKeyType = getError(51008, "Account Error,unknown key type");
    public static String NullInput = getError(51009, "Account Error,null input");
    public static String InvalidData = getError(51010, "Account Error,invalid data");

    //signature error
    public static String UnknownCurve = getError(52001, "Curve Error,unknown curve");
    public static String UnknownCurveLabel = getError(52002, "Curve Error,unknown curve label");
    public static String UnknownAsymmetricKeyType = getError(52003, "keyType Error,unknown asymmetric key type");
    public static String InvalidSignatureData = getError(52004, "Signature Error,invalid signature data: missing the ID parameter for SM3withSM2");
    public static String InvalidSignatureDataLen = getError(52005, "Signature Error,invalid signature data length");
    public static String MalformedSignature = getError(52006, "Signature Error,malformed signature");
    public static String UnsupportedSignatureScheme = getError(52007, "Signature Error,unsupported signature scheme:");
    public static String SignatureSchemeMismatch = getError(52008, "Signature Error, signature scheme mismatch");

    //OntIdTx Error
    public static String ParamError = getError(53001, "param error,");

    public static String OtherError(String msg) {
        return getError(54000, "Other Error," + msg);
    }
}
