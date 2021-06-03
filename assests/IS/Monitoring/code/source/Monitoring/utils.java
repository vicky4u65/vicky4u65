package Monitoring;

// -----( IS Java Code Template v1.2

import com.wm.data.*;
import com.wm.util.Values;
import com.wm.app.b2b.server.Service;
import com.wm.app.b2b.server.ServiceException;
// --- <<IS-START-IMPORTS>> ---
import iaik.security.rsa.RSAPublicKey;
import iaik.x509.X509Certificate;
import com.wm.util.JournalLogger;
import com.softwareag.util.IDataMap;
import com.wm.app.b2b.client.Context;
import com.wm.lang.ns.*;
import java.util.Hashtable;
import java.io.*;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.net.MalformedURLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import com.wm.app.b2b.server.*;
import com.wm.lang.ns.NSName;
import com.wm.app.b2b.server.ns.Namespace;
import com.wm.lang.ns.NSNode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.management.JMX;
import javax.management.MBeanServerConnection;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import java.util.concurrent.*;
import com.wm.app.b2b.server.cache.CacheManagerUtil;
import com.wm.app.b2b.server.lic.ComponentInfo;
import com.wm.app.b2b.server.lic.KeyInfo;
// --- <<IS-END-IMPORTS>> ---

public final class utils

{
	// ---( internal utility methods )---

	final static utils _instance = new utils();

	static utils _newInstance() { return new utils(); }

	static utils _cast(Object o) { return (utils)o; }

	// ---( server methods )---




	public static final void checkCertFile (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(checkCertFile)>> ---
		// @subtype unknown
		// @sigtype java 3.5
		// [i] field:0:required certFile
		// [o] field:0:required expiresIn
		// [o] field:0:required expiresOn
		// [o] record:0:required certinfo
		// [o] - field:0:required subject
		// [o] - field:0:required exponent
		// [o] - field:0:required daysleft
		// [o] - field:0:required serial
		// [o] - field:0:required status
		// [o] - field:0:required message
		IDataCursor cursor = pipeline.getCursor();
		String certFile = (String)IDataUtil.get(cursor, "certFile");
		
		X509Certificate cert = null;
		long daysLeft = 0;
		Properties q = new Properties();
		 
		String message = (String)IDataUtil.get(cursor, "message");
		if (message == null) message = "";
		q.put("message", certFile); // add message but busts unique sort
		try {
			File f;
			if (certFile != null) {
		           f = new File(certFile);
		        } else {
		           throw new FileNotFoundException();
		        }
			
			cert = new X509Certificate(new FileInputStream(f));
			Date notAfter = cert.getNotAfter();
			IDataUtil.put(cursor, "expiresOn", DateFormat.getDateTimeInstance().format(notAfter));
			daysLeft = (notAfter.getTime() - System.currentTimeMillis()) / 86400000; // number of ms in a day
		
			try {
		          q.put("exponent", ((RSAPublicKey)cert.getPublicKey()).getPublicExponent().toString());
			} catch (ClassCastException cce) {
		          q.put("exponent", "N/A (DSA?)");
		        }
			q.put("subject", cert.getSubjectDN().getName());
			q.put("daysleft", daysLeft+"");
		        String serial = iaik.utils.Util.toString(cert.getSerialNumber().toByteArray());
			q.put("serial", "dec = " + cert.getSerialNumber().toString() + " / hex = " + serial);
		
			cert.checkValidity();
		
		        q.put("status", "ok");
		
		
		} catch (FileNotFoundException fnfe) {
			q.put("status", "file not found: " + certFile );
		        q.put("daysleft", "-99");
		        q.put("exponent", "0");
		} catch (IOException ioe) {
		        q.put("status", "I/O Exception reading cert: " + ioe.getMessage());
		} catch (CertificateExpiredException cee) {
			q.put("status", "expired");
			//daysLeft = -1; // the certificate has expired
		} catch (CertificateException ce) {
			q.put("status", "CertificateException: " + ce.getMessage().toString());
			q.put("message", "File is likely not a X.509 Certificate: " + certFile);
		        q.put("daysleft", "-99");
		        q.put("exponent", "0");
		} catch (Exception e) {
		        q.put("status", e.toString());
			q.put("message", "Error converting certificate file");
		}
		cursor.insertAfter("certinfo", new Values(q));
		IDataUtil.put(cursor, "expiresIn", ""+daysLeft);
		cursor.destroy(); 
		// --- <<IS-END>> ---

                
	}



	public static final void getDirName (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(getDirName)>> ---
		// @sigtype java 3.5
		// [o] field:0:required configDirName
		IDataCursor pipe=pipeline.getCursor();
		String pkgDir = File.separator + Service.getPackageName();
		String configDir = userDir + pkgFolder + pkgDir + cfgFolder;
		IDataUtil.put(pipe, "configDirName" , configDir );
		pipe.destroy();
		// --- <<IS-END>> ---

                
	}



	public static final void getFile (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(getFile)>> ---
		// @sigtype java 3.5
		// [i] field:0:required filePath
		// [o] field:0:required fileContent
		IDataMap im = new IDataMap(pipeline);
		StringBuilder sb;
		BufferedReader buf=null;
		try {
			InputStream is = new FileInputStream(im.getAsString("filePath")); 
			buf = new BufferedReader(new InputStreamReader(is)); 
			String line = buf.readLine(); sb = new StringBuilder(); 
			while(line != null)
			{
				sb.append(line).append("\n"); 
				line = buf.readLine(); 
			}
			String fileAsString = sb.toString();
			im.put("fileContent", fileAsString);
		} catch (FileNotFoundException e) {
			throw new ServiceException(e.getMessage());
		} catch (IOException e) {
			throw new ServiceException(e.getMessage());
		} 
		finally
		{
			try {
				if(buf!=null)
				{
					buf.close();
				}
			} catch (IOException e) {
				throw new ServiceException(e.getMessage());
			}
		}
		// --- <<IS-END>> ---

                
	}



	public static final void getGCCount (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(getGCCount)>> ---
		// @sigtype java 3.5
		// [o] record:0:required gcInfo
		// [o] - field:0:required jmxPort
		// [o] - field:0:required gc1_name
		// [o] - field:0:required gc1_count
		// [o] - field:0:required gc2_name
		// [o] - field:0:required gc2_count
		// [o] - field:0:required errorInfo
		//Getting GC port first.
		getJMXPort();
		
		IDataCursor pipelineCursor = pipeline.getCursor();
		pipelineCursor.insertAfter("gcInfo", new Values(q));
		pipelineCursor.destroy();
		
		q.clear();
			
		// --- <<IS-END>> ---

                
	}



	public static final void getHostName (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(getHostName)>> ---
		// @sigtype java 3.5
		// [o] field:0:required hostname
		IDataMap plm = new IDataMap(pipeline);
		plm.put("hostname", ServerAPI.getServerName());
			
		// --- <<IS-END>> ---

                
	}



	public static final void getLicenseExpiry (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(getLicenseExpiry)>> ---
		// @sigtype java 3.5
		// [o] field:0:required licenseKey
		// [o] field:0:required expirationDate
		String licenseKey = null;  
		String expirationDate = null;  
		for (ComponentInfo componentInfo : KeyInfo.getComponentInfo()){  
		    if (componentInfo.getComponentName().equals("SalesInfo")){  
		        IDataCursor componentInfoCursor = componentInfo.getComponentInfo().getCursor();  
		        IData salesInfo = IDataUtil.getIData(componentInfoCursor, "Sales Information");  
		        componentInfoCursor.destroy();  
		        IDataCursor salesInfoCursor = salesInfo.getCursor();  
		        licenseKey = IDataUtil.getString(salesInfoCursor, "License Key");  
		        salesInfoCursor.destroy();  
		    }  
		    if (componentInfo.getComponentName().equals("ProductInfo")){  
		        IDataCursor componentInfoCursor = componentInfo.getComponentInfo().getCursor();  
		        IData productInfo = IDataUtil.getIData(componentInfoCursor, "Product Information");  
		        componentInfoCursor.destroy();  
		        IDataCursor productInfoCursor = productInfo.getCursor();  
		        expirationDate = IDataUtil.getString(productInfoCursor, "Expiration Date");  
		        productInfoCursor.destroy();  
		    }  
		}  
		  
		IDataCursor pipelineCursor = pipeline.getCursor();  
		IDataUtil.put(pipelineCursor, "licenseKey", licenseKey);  
		IDataUtil.put(pipelineCursor, "expirationDate", expirationDate);  
		pipelineCursor.destroy(); 
		// --- <<IS-END>> ---

                
	}



	public static final void getLockedServiceList (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(getLockedServiceList)>> ---
		// @sigtype java 3.5
		// [i] record:0:required ALL_LOCKS
		// [o] field:1:required lockedServices
		IDataCursor pipelineCursor = pipeline.getCursor();
		
		// ALL_LOCKS
		String locked="";
		String[] lockedItems={};
		String[] newLockedList={};
		   
		IData	ALL_LOCKS = IDataUtil.getIData( pipelineCursor, "ALL_LOCKS" );
		if ( ALL_LOCKS != null)
		{
		}
		
		locked=ALL_LOCKS.toString();
		lockedItems=locked.split(",");
		
		       int j=0;
		       ArrayList<String> finalList=new ArrayList<>();
		       //String[] finalList=new String[lockedItems.length];
			for(int i=0;i<lockedItems.length;i=i+4){
					newLockedList=lockedItems[i].split("= >>>");
					
					finalList.add(newLockedList[0]);
					//j++;
					}
			
			pipelineCursor.destroy();
		
		
		
			Object[] objeLocked=finalList.toArray();
			String[] lockedFinalList = Arrays.copyOf(objeLocked, objeLocked.length, String[].class);
		IDataCursor pipelineCursor_1 = pipeline.getCursor();
		String[]	lockedServices = new String[1];
		lockedServices[0] = "lockedServices";
		
		IDataUtil.put( pipelineCursor_1, "lockedServices",lockedFinalList);
		pipelineCursor_1.destroy();
		// --- <<IS-END>> ---

                
	}

	// --- <<IS-START-SHARED>> ---
	private static final String userDir = System.getProperty("user.dir");
	private static final String pkgFolder = File.separator + "packages";
	private static final String cfgFolder = File.separator + "config";
	static Properties q = new Properties();
	static void getJMXPort(){
		
		if (System.getProperty("com.sun.management.jmxremote")==null)
		{
			q.put("errorInfo", "JMX remote is disabled please follow instructions as mentioned in comments");
			//return  "JMX remote is disabled" + "please follow instructions as mentioned in comments";
		}else
		{
			String a=System.getProperty("com.sun.management.jmxremote.port");
			if(a!=null)
			{
				q.put("jmxPort", a);
				getGcCount(a); // calling gc Count method
			}
			else
			{
				q.put("errorInfo", "JMX port is not set properly please follow instructions as mentioned in comments");
			}
		}
	}
	
	static Properties getGcCount(String port)
	{
		int i=1;
		try{
			for(GarbageCollectorMXBean bean : ManagementFactory.getGarbageCollectorMXBeans())
			{
				q.put("gc"+i+"_name",bean.getName());
				q.put("gc"+i+"_count",String.valueOf(bean.getCollectionCount()));
				
				i++;
			}
			if(i<=1)
			{
				q.put("errorInfo", "No garbageCollector Found");
			}
			
		}catch(Exception e)
		{
			q.put("errorInfo", e.toString());
		}
		
		return q;
	}
	// --- <<IS-END-SHARED>> ---
}

