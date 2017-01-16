package com.hzih.sslvpn.web.action.sslvpn.client.check;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

import java.io.*;
import java.security.cert.*;
import java.util.Date;

/**
 * Created with IntelliJ IDEA.
 * User: hhm
 * Date: 14-7-3
 * Time: 下午9:33
 * To change this template use File | Settings | File Templates.
 */
public class CertificateUtils {

    public void checkValidity(X509CertificateStructure certificateStructure) throws CertificateExpiredException, CertificateNotYetValidException {
        Date date = new Date();
        if(date.getTime() > certificateStructure.getEndDate().getDate().getTime()) {
            throw new CertificateExpiredException("certificate expired on " + certificateStructure.getEndDate().getTime());
        } else if(date.getTime() < certificateStructure.getStartDate().getDate().getTime()) {
            throw new CertificateNotYetValidException("certificate not valid till " + certificateStructure.getStartDate().getTime());
        }
    }

    public static  X509CertificateStructure get_x509_certificate(File derFile) {
        try{
            InputStream inStream = new FileInputStream(derFile);
            ASN1InputStream aIn = new ASN1InputStream(inStream);
            ASN1Sequence seq  = (ASN1Sequence) aIn.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);
            return cert;
        }catch (Exception e){
            return null;
        }
    }
}
