/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015, Red Hat, Inc. and/or its affiliates, and individual
 * contributors by the @authors tag. See the copyright.txt in the
 * distribution for a full listing of individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * REST service queries ldap and gives the result in Json format
 *
 * Yu Shao <yshao@redhat.com>
 */

package org.jboss.as.quickstarts.ldapjson;

import java.util.*;
import javax.inject.Inject;
import javax.ws.rs.POST;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

import javax.net.SocketFactory;

import javax.net.ssl.*;
import java.security.cert.*;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.KeyStoreException;
import java.security.KeyManagementException;

import java.io.PrintStream;
import java.io.FileInputStream;
import java.io.InputStream;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdapLdifException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.api.ldap.model.cursor.Cursor;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.*;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.*;
import org.apache.directory.api.ldap.model.cursor.*;
import org.apache.directory.api.ldap.model.exception.*;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import java.io.File;
import java.io.FileWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.io.IOException;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.MinimalPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;





@Path("/")
public class ldapjson {

    @GET
    @Path("/ldapentry/{ldapServer}/{baseDN}/{filter}")
    @Produces("application/json")
    public String getldapjson(@PathParam("ldapServer") String ldapServer,
                              @PathParam("baseDN") String baseDN,
                              @PathParam("filter") String filter) {
        System.out.println("Server: " + ldapServer);
        System.out.println("baseDN: " + baseDN);
        System.out.println("Filter: " + filter);
        String indented = null;




        try {



            SocketFactory socketfactory = SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) socketfactory.createSocket(ldapServer, 636);
            socket.startHandshake();

            Certificate[] certs = socket.getSession().getPeerCertificates();

            System.out.println("Certs retrieved: " + certs.length + ", building KeyStore...");

	 
    	    String keyStoreType = KeyStore.getDefaultType();
	    KeyStore keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(null, null);

            for (Certificate cert : certs) {
                if(cert instanceof X509Certificate) {
                    ( (X509Certificate) cert).checkValidity();
                    System.out.println("Active certificate, DN: " + ((X509Certificate) cert).getSubjectDN().getName() + ".");
	    	    keyStore.setCertificateEntry(((X509Certificate) cert).getSubjectDN().getName(), ((X509Certificate) cert) );
                }
            }

            System.out.println("Finish building KeyStore, size:  " + keyStore.size() + ".");


            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
	    tmf.init(keyStore);
            TrustManager[] tm = tmf.getTrustManagers();
            
            System.out.println("Connecting server ...");
           
            LdapConnectionConfig tlsConfig = new LdapConnectionConfig();

            tlsConfig.setLdapHost( ldapServer );
            tlsConfig.setLdapPort( 389 );
            tlsConfig.setUseTls( true );
            //tlsConfig.setUseSsl( true );
            System.out.println("tm =  : " + tm);
            tlsConfig.setTrustManagers( tm );
            //tlsConfig.setTrustManagers( null );
      
            //System.out.println("getcredentials = " + tlsConfig.getCredentials());

            //LdapNetworkConnection connection = new LdapNetworkConnection( tlsConfig );

            LdapNetworkConnection connection = new LdapNetworkConnection( tlsConfig );
            System.out.println("Connection Secure : \n" + connection.isSecured());

            connection.connect();
            System.out.println("after connect Connection Secure or not : \n" + connection.isSecured());
            connection.startTls();
            System.out.println("Connection Secure : \n" + connection.isSecured());

            /*
            for (TrustManager eachTm : tm) {
		if (eachTm instanceof X509TrustManager) {
                        System.out.println("after starttls******x509 cert ");
			X509TrustManager tmDelegate = (X509TrustManager) eachTm;
			//tmDelegate.checkServerTrusted(chain,null);
			//tmDelegate.checkClientTrusted(chain,null);
                        //System.out.println("ca=" + ((X509Certificate) eachTm).getSubjectDN());
		}
	     }               
            */ 

            //connection.bind( "uid=admin,ou=system", "secret" );
            connection.bind();

            System.out.println("Connection Secure or not : \n" + connection.isSecured());


            //connection.startTls();
            //System.out.println("Connection Secure or not : \n" + connection.isSecured());

            //LdapConnection connection = new LdapNetworkConnection( ldapServer, 389 );

            //EntryCursor cursor = connection.search( "ou=users,dc=redhat,dc=com", "(rhathiredate>=20171106000000Z)", SearchScope.ONELEVEL );

            EntryCursor cursor = connection.search( baseDN,
                                                    filter, 
                                                    SearchScope.ONELEVEL, 
                                                    "*","+" );

            JsonFactory factory = new JsonFactory();

            Writer stringWriter=new StringWriter();
            JsonGenerator generator = factory.createGenerator(stringWriter);

            int cursorSize = 0;

            generator.writeStartObject();


            generator.writeArrayFieldStart("New Employee List");

            for ( Entry entry : cursor )
                {
                    cursorSize++;

                    generator.writeStartObject();

                    for (Attribute thisAttribute : entry ) {
                       int valueSize = thisAttribute.size();

                       switch (thisAttribute.getId().toLowerCase()) {

                           case "usercertificate":
                               /* Ignore the binary value */
                               break;
                           case "jpegphoto":
                               /* Ignore the binary jpeg value */
                               break;
                           case "manager":
                               generator.writeFieldName(thisAttribute.getId());
                               String mgrDN = thisAttribute.getString();
                               ObjectMapper mgrMapper = new ObjectMapper();
                               HashMap<String, String> mgrHolder = new HashMap();
                               String[] mgrkeyVals = mgrDN.split(",");
                               for(String mgrkeyVal:mgrkeyVals)
                               {
                                 String[] parts = mgrkeyVal.split("=",2);
                                 if (!parts[0].equals("dc")) mgrHolder.put(parts[0],parts[1]);
                               }
                               String mgrJsonString = mgrMapper.writeValueAsString(mgrHolder);
                               generator.writeRawValue(mgrJsonString);
                               break;
                           case "memberof":
                               generator.writeArrayFieldStart(thisAttribute.getId());
                               for ( Value<?> value : thisAttribute ) {
                                   String searchBase = value.getString();
                                   ObjectMapper mapper = new ObjectMapper();
                                   HashMap<String, String> holder = new HashMap();
                                   String[] keyVals = searchBase.split(",");
                                   for(String keyVal:keyVals)
                                   {
                                     String[] parts = keyVal.split("=",2);
                                     if (!parts[0].equals("dc")) holder.put(parts[0],parts[1]);
                                   }
                                   String jsonString = mapper.writeValueAsString(holder);
                                   generator.writeRawValue(jsonString);
                               }
                               generator.writeEndArray();
                               break;
                           case "rhatweblogin":
                               generator.writeArrayFieldStart(thisAttribute.getId());
                               for ( Value<?> value : thisAttribute ) {
                                   generator.writeString(value.getString());
                               }
                               generator.writeEndArray();
                               break;
                           default:
                               if (valueSize > 1) {
                                   generator.writeArrayFieldStart(thisAttribute.getId());
                                   for ( Value<?> value : thisAttribute ) {
                                       generator.writeString(value.getString());
                                   }
                                   generator.writeEndArray();
                               } else {
                                   //System.out.println("Field name : " + thisAttribute.getId());
                                   //System.out.println("Field value : " + thisAttribute.getString());
                                   generator.writeFieldName(thisAttribute.getId());
                                   generator.writeString(thisAttribute.getString());
                               }
                               break;
                       } /* switch */

                    } /* Attribute for */

                    generator.writeEndObject();

            } /* Entry for */

            cursor.close();
            generator.writeEndArray();
            generator.writeFieldName("Total New");
            generator.writeNumber(cursorSize);
            generator.writeFieldName("LDAP Server");
            generator.writeString(ldapServer);
            generator.writeFieldName("Base DN");
            generator.writeString(baseDN);
            generator.writeFieldName("Filter");
            generator.writeString(filter);
            generator.writeEndObject();
  
            generator.close();

            ObjectMapper mapper = new ObjectMapper();
            Object jsonObject = mapper.readValue(stringWriter.toString(), Object.class);
            indented = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject);

            //System.out.println("Generated Json : \n" + indented);

            System.out.println("Closing connection ...");
            connection.close();
        } catch(CertificateExpiredException cee) {
             System.out.println("Certificate is expired");
        } catch (LdapException e) {
            System.out.println("LDAP Exception : " + e.getMessage());
            return ("{ \"Error\": \"" + e.getMessage() + "\" }");
	} catch (NoSuchAlgorithmException e) {
		e.printStackTrace();
	} catch (KeyStoreException e) {
		e.printStackTrace();
	//} catch (KeyManagementException e) {
        //		e.printStackTrace();
	} catch (CertificateException e) {
		e.printStackTrace();
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
		e.printStackTrace();
            return ("{ \"Error\": \"" + e.getMessage() + "\" }");
            
        }


        return indented;

    } /*function*/

} /* class */
