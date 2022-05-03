package com.github.ontid.common;

import com.github.ontid.core.VerifiablePresentation;
import junit.framework.TestCase;

public class HelperTest extends TestCase {

    public void testCheckURI() {
        boolean boo = Helper.checkURI("ccea8055-ec09-4d9e-8a0d-60aa55ee38a1");
        System.out.println(boo);
    }

    public void testCheckIssuerValid() {
        VerifiablePresentation vp = new VerifiablePresentation();
        boolean boo = Helper.checkIssuerValid(vp);
        System.out.println(boo);
    }
    public void testCheckStructUri() {
        VerifiablePresentation vp = new VerifiablePresentation();
        boolean boo = Helper.checkStructUri(vp);
        System.out.println(boo);
    }
}
