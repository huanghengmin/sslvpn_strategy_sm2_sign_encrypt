package com.hzih.sslvpn.web.action.sslvpn.client.check;

import com.hzih.sslvpn.dao.UserDao;
import com.hzih.sslvpn.domain.User;
import com.hzih.sslvpn.utils.FileUtil;
import com.hzih.sslvpn.utils.StringContext;
import com.hzih.sslvpn.utils.md5.MD5Utils;
import com.hzih.sslvpn.web.action.sslvpn.encrypt.EncryptUtils;
import com.hzih.sslvpn.web.action.sslvpn.encrypt.config.X509Context;
import com.hzih.sslvpn.web.action.sslvpn.encrypt.config.X509Entity;
import com.hzih.sslvpn.web.action.sslvpn.encrypt.config.X509ShellUtils;
import com.hzih.sslvpn.web.action.sslvpn.utils.ByteFileUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;
import org.bouncycastle.asn1.x509.X509CertificateStructure;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.Date;

/**
 * Created by Administrator on 15-12-10.
 */
public class CheckAction {
    private UserDao userDao;
    private Logger logger = Logger.getLogger(getClass());

    public UserDao getUserDao() {
        return userDao;
    }

    public void setUserDao(UserDao userDao) {
        this.userDao = userDao;
    }

    public boolean checkCertificats(String caFile, String certFile) {
        return X509ShellUtils.build_verify(caFile,certFile);
    }

    public String check() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        response.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        String certificate = request.getParameter("certificate");
        String osType = request.getParameter("osType");
        String ca_file_md5 = request.getParameter("ca_file_md5");
        String cert_file_md5 = request.getParameter("cert_file_md5");
        String key_file_md5 = request.getParameter("key_file_md5");
        String json = null;
        String msg = null;
        if (certificate != null) {
            byte[] getBytes = Base64.decodeBase64(certificate.getBytes());
            String cerPath = StringContext.temp+"/temp"+ X509Context.certName;
            String derPath = StringContext.temp+"/temp"+ X509Context.derName;
            FileUtil.copy(getBytes,derPath);
            boolean f = X509ShellUtils.build_der_pem(
                    derPath,
                    cerPath);
            if(f){
                File file = new File(derPath);
                X509CertificateStructure x509CertificateStructure = CertificateUtils.get_x509_certificate(file);
                try {
                    String subject = x509CertificateStructure.getSubject().toString();
                    logger.info("subject:"+subject);
                    String serialNumber = x509CertificateStructure.getSerialNumber().getValue().toString(16);
//                    boolean checkCertificats_flag = checkCertificats(StringContext.sign_ca_file, cerPath);
//                    if (checkCertificats_flag) {
//                        //检验吊销
//                        boolean exist = CheckCRLUtils.checkCRL(serialNumber);
//                        if (exist) {
//                            msg = "签名证书已被吊销！";
//                            json = "{\"success\":false,\"msg\":\"" + msg + "\"}";
//                            logger.error("serialNumber:" + serialNumber + ",msg:" + msg + ",时间:" + new Date());
//                            writer.write(json);
//                            writer.close();
//                            return null;
//                        }
                        String[] subjects = subject.split(",");
                        for (String s : subjects) {
                            if (s.contains("CN=")) {
                                logger.info("CN="+s);
                                if (s.contains("=")) {
                                    String[] ss = s.split("=");
                                    X509Entity clientEntity = new X509Entity();
                                    String trimCN = ss[1].replaceAll("\\s*", "");
                                    clientEntity.setCN(trimCN);
                                    clientEntity.setSerialNumber(serialNumber);
                                    if (clientEntity != null) {
                                        boolean flag = EncryptUtils.findClient(clientEntity);
                                        if (!flag) {
                                            boolean save = EncryptUtils.buildClient(clientEntity);
                                            if (save) {
                                                User query_user = userDao.findByCommonName(clientEntity.getCN());
                                                if (query_user != null) {
                                                    if (!query_user.getSerial_number().equals(clientEntity.getSerialNumber())) {
                                                        query_user.setSerial_number(clientEntity.getSerialNumber());
                                                        userDao.modify(query_user);
                                                    }
                                                } else {
                                                    User user = new User();
                                                    user.setCn(clientEntity.getCN());
                                                    user.setSerial_number(clientEntity.getSerialNumber());
                                                    userDao.add(user);
                                                }
                                            }
                                        } else {
                                            //校验禁用
                                            User query_user = userDao.findByCommonName(clientEntity.getCN());
                                            if (query_user != null) {
                                                if (query_user.getEnabled() != 1) {
                                                    msg = "客户端已被禁用！";
                                                    json = "{\"success\":false,\"msg\":\"" + msg + "\"}";
                                                    logger.error("serialNumber:" + serialNumber + ",msg:" + msg + ",时间:" + new Date());
                                                    writer.write(json);
                                                    writer.close();
                                                    return null;
                                                }
                                            }
                                        }
                                        flag = EncryptUtils.findClient(clientEntity);
                                        if (flag) {
                                            File keyFile = EncryptUtils.getClientKey(clientEntity);
                                            File certFile = EncryptUtils.getClientCert(clientEntity);
                                            File CaFile = EncryptUtils.getCAFile(EncryptUtils.getCA());
                                            File ConfFile = null;
                                            if (osType.equals("x86")) {
                                                ConfFile = new File(StringContext.windows_config_file);
                                            } else if (osType.equals("x64")) {
                                                ConfFile = new File(StringContext.windows_config_file);
                                            } else if (osType.equals("Android")) {
                                                ConfFile = new File(StringContext.android_config_file);
                                            }

                                            String key_md5 = MD5Utils.getMd5ByFile(keyFile);
                                            String crt_md5 = MD5Utils.getMd5ByFile(certFile);
                                            String ca_md5 = MD5Utils.getMd5ByFile(CaFile);
                                            String config_md5 = MD5Utils.getMd5ByFile(ConfFile);
                                            boolean compare = false;

                                            if (key_file_md5 != null && key_file_md5.equals(key_md5)
                                                    && cert_file_md5 != null && cert_file_md5.equals(crt_md5)
                                                    && ca_file_md5 != null && ca_file_md5.equals(ca_md5)) {
                                                compare = true;
                                            }

                                            if (!compare) {
                                                String key = new String(Base64.encodeBase64(ByteFileUtils.File2byte(keyFile)));
                                                String crt = new String(Base64.encodeBase64(ByteFileUtils.File2byte(certFile)));
                                                String ca = new String(Base64.encodeBase64(ByteFileUtils.File2byte(CaFile)));
                                                String config = new String(Base64.encodeBase64(ByteFileUtils.File2byte(ConfFile)));
                                                msg = "compare false";
                                                json = "{\"success\":true" + "," +
                                                        "\"compare\":false," +
                                                        "\"msg\":\"" + msg + "\"" + "," +
                                                        "\"key\":\"" + key + "\"" + "," +
                                                        "\"key_md5\":\"" + key_md5 + "\"" + "," +
                                                        "\"crt\":\"" + crt + "\"" + "," +
                                                        "\"crt_md5\":\"" + crt_md5 + "\"" + "," +
                                                        "\"ca\":\"" + ca + "\"" + "," +
                                                        "\"ca_md5\":\"" + ca_md5 + "\"" + "," +
                                                        "\"config\":\"" + config + "\"" + "," +
                                                        "\"config_md5\":\"" + config_md5 + "\"" +
                                                        "}";
                                                writer.write(json);
                                                writer.close();
                                            } else {
                                                msg = "compare true";
                                                json = "{\"success\":true" + "," +
                                                        "\"compare\":true," +
                                                        "\"msg\":\"" + msg + "\"" + "," +
                                                        "\"key\":\"\"" + "," +
                                                        "\"key_md5\":\"\"" + "," +
                                                        "\"crt\":\"\"" + "," +
                                                        "\"crt_md5\":\"\"" + "," +
                                                        "\"ca\":\"\"" + "," +
                                                        "\"ca_md5\":\"\"" + "," +
                                                        "\"config\":\"\"" + "," +
                                                        "\"config_md5\":\"\"" +
                                                        "}";
                                                writer.write(json);
                                                writer.close();
                                            }
                                            return null;
                                        } else {
                                            msg = "生成证书失败！";
                                            json = "{\"success\":false,\"msg\":\"" + msg + "\"}";
                                            logger.error("serialNumber:" + serialNumber + ",msg:" + msg + ",时间:" + new Date());
                                            writer.write(json);
                                            writer.close();
                                            return null;
                                        }
                                    }
                                }
                            }
                        }
                    /*} else {
                        msg = "证书签名校验失败！";
                        json = "{\"success\":false,\"msg\":\"" + msg + "\"}";
                        logger.error("serialNumber:" + serialNumber + ",msg:" + msg + ",时间:" + new Date());
                        writer.write(json);
                        writer.close();
                        return null;
                    }*/

                } catch (Exception e) {
                    msg = "客户端签名证书读取失败！";
                    ;
                    json = "{\"success\":false,\"msg\":\"" + msg + "\"}";
                    logger.error("remoteIp:" + request.getRemoteAddr() + ",msg:" + msg + ",时间:" + new Date());
                    writer.write(json);
                    writer.close();
                    return null;
                }
            }
        }
        return null;
    }

    /*public static void main(String args[])throws Exception{
        String subject = "CN = \"范 郑\",OU=\"sss\"";
        String[] subjects = subject.split(",");
        for (String s : subjects) {
            if (s.contains("CN")) {
                if (s.contains("=")) {
                    String[] ss = s.split("=");
                    String trimCN = ss[1].replaceAll("\\s*", "");
                    System.out.print(trimCN);
                }
            }
        }
    }*/
}
