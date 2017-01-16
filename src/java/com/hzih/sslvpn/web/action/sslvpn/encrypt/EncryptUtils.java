package com.hzih.sslvpn.web.action.sslvpn.encrypt;


import com.hzih.sslvpn.web.action.sslvpn.client.check.CertificateUtils;
import com.hzih.sslvpn.web.action.sslvpn.encrypt.config.*;
import org.bouncycastle.asn1.x509.X509CertificateStructure;

import java.io.File;

/**
 * Created by Administrator on 15-12-7.
 */
public class EncryptUtils {

    public static X509Entity getCA() {
        X509Entity x509Entity = new X509Entity();
        x509Entity.setCN("ZD");
        x509Entity.setType(X509Context.sm2);
        x509Entity.setKeyLength(256);
        return x509Entity;
    }

    public static boolean findCA(X509Entity entity) {
        //CA 目录
        String storeDirectory = X509Context.store_path + "/" + entity.getCN();
        //CA 证书目录
        String selfDirectory = DirectoryUtils.getSuperStoreDirectory(storeDirectory);
        //证书文件
        File cerFile = new File(selfDirectory + "/" + entity.getCN() + X509Context.certName);
        File keyFile = new File(selfDirectory + "/" + entity.getCN() + X509Context.keyName);
        if (keyFile.exists() && keyFile.length() > 0 && cerFile.exists() && cerFile.length() > 0) {
            return true;
        }
        return false;
    }

    public static X509Entity getServer() {
        X509Entity x509Entity = new X509Entity();
        x509Entity.setCN("Server");
        return x509Entity;
    }

    public static boolean findServer(X509Entity entity) {
        //CA 信息
        X509Entity cAEntity = EncryptUtils.getCA();
        //CA 目录
        String storeDirectory = X509Context.store_path + "/" + cAEntity.getCN();
        //证书文件
        File cerFile = new File(storeDirectory + "/" + entity.getCN() + X509Context.certName);
        File keyFile = new File(storeDirectory + "/" + entity.getCN() + X509Context.keyName);
        if (keyFile.exists() && keyFile.length() > 0 && cerFile.exists() && cerFile.length() > 0) {
            return true;
        }
        return false;
    }

    public static boolean findClient(X509Entity entity) {
        //CA 信息
        X509Entity cAEntity = EncryptUtils.getCA();
        //CA 目录
        String storeDirectory = X509Context.store_path + "/" + cAEntity.getCN();
        //证书文件
        File derFile = new File(storeDirectory + "/" + entity.getCN() + X509Context.derName);
        if (derFile.exists() && derFile.length() > 0) {
            X509CertificateStructure x509CertificateStructure = CertificateUtils.get_x509_certificate(derFile);
            if (x509CertificateStructure != null) {
                String subject = x509CertificateStructure.getSubject().toString();
                String[] subjects = subject.split(",");
                for (String s : subjects) {
                    if (s.contains("CN")) {
                        if (s.contains("=")) {
                            String[] ss = s.split("=");
                            if (entity.getCN().equals(ss[1])) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    public static boolean buildClient(X509Entity entity) {
        //CA 信息
        X509Entity cAEntity = EncryptUtils.getCA();
        //CA 目录
        String storeDirectory = X509Context.store_path + "/" + cAEntity.getCN();
        //CA 证书目录
        String selfDirectory = DirectoryUtils.getSuperStoreDirectory(storeDirectory);
        //构建用户请求文件
        boolean flag = X509UserConfigUtils.buildUser(entity, storeDirectory);
        if (flag) {
            //构建csr请求
            if (cAEntity.getType().equals(X509Context.rsa)) {
                flag = X509ShellUtils.build_csr(String.valueOf(cAEntity.getKeyLength()),
                        storeDirectory + "/" + entity.getCN() + X509Context.keyName,
                        storeDirectory + "/" + entity.getCN() + X509Context.csrName,
                        storeDirectory + "/" + entity.getCN() + X509Context.config_type_certificate);
            } else {
                flag = X509ShellUtils.build_sm2_key(String.valueOf(cAEntity.getKeyLength()),
                        storeDirectory + "/" + entity.getCN() + X509Context.keyName);
                if (flag) {
                    flag = X509ShellUtils.build_sm2_csr(
                            storeDirectory + "/" + entity.getCN() + X509Context.keyName,
                            storeDirectory + "/" + entity.getCN() + X509Context.csrName,
                            storeDirectory + "/" + entity.getCN() + X509Context.config_type_certificate);
                }
            }
            if (flag) {
                //签发用户CA
                if (cAEntity.getType().equals(X509Context.rsa)) {
                    flag = X509ShellUtils.build_sign_csr(storeDirectory + "/" + entity.getCN() + X509Context.csrName,
                            storeDirectory + "/" + cAEntity.getCN() + X509Context.config_type_ca,
                            X509Context.certificate_type_client, selfDirectory + "/" +
                                    cAEntity.getCN() + X509Context.certName, selfDirectory + "/" +
                                    cAEntity.getCN() + X509Context.keyName, storeDirectory + "/" +
                                    entity.getCN() + X509Context.certName, String.valueOf(X509Context.default_certificate_validity));
                } else {
                    flag = X509ShellUtils.build_sign_sm2_csr(storeDirectory + "/" + entity.getCN() + X509Context.csrName,
                            storeDirectory + "/" + cAEntity.getCN() + X509Context.config_type_ca,
                            X509Context.certificate_type_client, selfDirectory + "/" +
                                    cAEntity.getCN() + X509Context.certName, selfDirectory + "/" +
                                    cAEntity.getCN() + X509Context.keyName, storeDirectory + "/" +
                                    entity.getCN() + X509Context.certName, String.valueOf(X509Context.default_certificate_validity));
                }
                if (flag) {
                    File cerFile = new File(storeDirectory + "/" + entity.getCN() + X509Context.certName);
                    File keyFile = new File(storeDirectory + "/" + entity.getCN() + X509Context.keyName);
                    if (keyFile.exists() && keyFile.length() > 0 && cerFile.exists() && cerFile.length() > 0) {
                        boolean f = X509ShellUtils.build_pem_der(
                                storeDirectory + "/" + entity.getCN() + X509Context.certName,
                                storeDirectory + "/" + entity.getCN() + X509Context.derName);
                        if (f)
                            return true;
                    }
                }
            }
        }
        return false;
    }

    public static File getCAFile(X509Entity entity) {
        //证书文件
        File cerFile = new File(X509Context.store_path + "/" + entity.getCN() + X509Context.certName);
        if (cerFile.exists() && cerFile.length() > 0) {
            return cerFile;
        }
        return null;
    }

    public static File getClientKey(X509Entity entity) {
        //CA 信息
        X509Entity cAEntity = EncryptUtils.getCA();
        //CA 目录
        String storeDirectory = X509Context.store_path + "/" + cAEntity.getCN();
        //证书文件
        File keyFile = new File(storeDirectory + "/" + entity.getCN() + X509Context.keyName);
        if (keyFile.exists() && keyFile.length() > 0) {
            return keyFile;
        }
        return null;
    }

    public static File getClientCert(X509Entity entity) {
        //CA 信息
        X509Entity cAEntity = EncryptUtils.getCA();
        //CA 目录
        String storeDirectory = X509Context.store_path + "/" + cAEntity.getCN();
        //证书文件
        File certFile = new File(storeDirectory + "/" + entity.getCN() + X509Context.certName);
        if (certFile.exists() && certFile.length() > 0) {
            return certFile;
        }
        return null;
    }
}
