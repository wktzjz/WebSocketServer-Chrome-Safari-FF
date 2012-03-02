<!--
  Speed Test for bmp_lib.js

  Copyright 2008 Neil Fraser.
  http://neil.fraser.name/software/bmp_lib/

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->



import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
//import java.lang.reflect.Array;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.Channel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sun.media.sound.InvalidDataException;

import sun.misc.BASE64Encoder;


public class WebSocketServer extends ServerSocket {
	
	private static final int SERVER_PORT = 5555;

	public WebSocketServer() throws IOException {
		super(SERVER_PORT);

		try {
			while (true) {
				Socket socket = accept();
				new Sever1(socket);
			}
		} catch (IOException e) {
		} finally {
			close();
		}
	}

	public static void main(String[] args) throws IOException {

		new WebSocketServer();
	}


class Sever1 extends Thread {
	private Socket socket;
	private ServerSocket ws;
	private InputStream in;
	private OutputStream out;
	private String key="";
	private String key1="";
	private String key2="";
	private byte[] key3=new byte[8];
    private int browser;
    private boolean flag=false;
    private int count;
    private String req="";
    private byte b[] = new byte[40000];
    
    public Sever1(Socket s) throws IOException{
    	socket = s;
		in = socket.getInputStream();
		out = socket.getOutputStream();
		start();
	}

	public void run() {	
		
		try {
			while (true) {			
				if(!flag){			
				int temp=0;
				int len=0; 			
				count = in.read(b);				
				req = new String(b);
				/*while((temp=in.read())!=-1)
				{
					b[len]=(byte)temp;
					len++;
				}
				in.close(); 
				 req = new String(b, 0, len);*/
				System.out.println(req);
				}	
			if (req.contains("Sec-WebSocket-Key1")) {//Safari browser			
				for (int i = 0; i < 8; i++) {
					key3[i]=b[count-8+i];
				}
				if(!flag){
				Pattern p = Pattern.compile("^(Sec-WebSocket-Key1:).+",
							Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
					Matcher m = p.matcher(req);
					if (m.find()) {
						String foundstring = m.group();
						key1 = foundstring.split(":")[1].trim();
					}

					Pattern p1 = Pattern.compile("^(Sec-WebSocket-Key2:).+",
							Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
					Matcher m1 = p1.matcher(req);
					if (m1.find()) {
						String foundstring1 = m1.group();
						key2 = foundstring1.split(":")[1].trim();
					}

					System.out.println("********************************");
					System.out.println("key1:" + key1);
					System.out.println("key2:" + key2);
				    System.out.println("key3:"+ byte2hex(key3));
				    System.out.println("key3:" + new String(key3));				
				/*	int spaceNum1 = key1.length()- (key1.replaceAll(" ", "")).length();
					int spaceNum2 = key2.length()- (key2.replaceAll(" ", "")).length();
					int digNum1 = key1.length()- (key1.replaceAll("\\d", "")).length();
					int digNum2 = key2.length()- (key2.replaceAll("\\d", "")).length();
					int keyNum1 = (int) Math.ceil(digNum1 / spaceNum1);
					int keyNum2 = (int) Math.ceil(digNum2 / spaceNum2);*/
				    
					String response = "HTTP/1.1 101 Web Socket Protocol Handshake\r\nConnection: Upgrade\r\nSec-WebSocket-Location: ws://localhost:5555/\r\nSec-WebSocket-Origin: file://\r\nUpgrade: WebSocket\r\n\r\n";
					//		+ createChallenge(key1, key2, key3) + "\r\n";
					out.write(response.getBytes());
					out.write(createChallenge(key1, key2, key3));
					System.out.println("���ظ���������response:" + response+byte2hex(createChallenge(key1, key2, key3)));
				flag = true;
				}	
					byte b1[] = new byte[500];
					int count1 = in.read(b1);
					if (count1 == -1)break;// count=-1 page refreah,break to jump out of while					
					String msg= new String(b1,1,count1-2);
					System.out.println("���յ�����Ϣ:" + msg);			
					out.write(b1);				
					
			} else { //Chrome or FF
			      key = getSecWebSocketKey(req);
			   
			      chromeFF(key);		
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	
	private void chromeFF(String key) throws IOException
	{
		if(!flag){
		System.out.println("*************************************");
		System.out.println("Sec-WebSocket-Key:" + key);
		String response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
				+ getSecWebSocketAccept(key) + "\r\n\r\n";	
		System.out.println("Sec-WebSocket-Accept:"
				+ getSecWebSocketAccept(key));
		out.write(response.getBytes(),0,response.getBytes().length);
		flag=true;
		}
		
		while (true) {
			byte b[] = new byte[40000];
			byte pushHead[] = null;
			int count1 = in.read(b);
			if (count1 == -1)break;// count=-1 page refreah,break to jump out of while
			System.out.println("���յ����ֽ���:" + count1);
			byte mask[] = new byte[4];
			byte d[] = null;
			int code_length = (b[1]) & 127;
			System.out.println("msg length"+code_length);
			switch (code_length) {
			case 126:
				d = new byte[count1 - 8];
				for (int i = 0; i < 4; ++i) {
					mask[i] = b[i + 4];
				}
				for (int i = 0; i < count1 - 8; i++) {
					d[i] = (byte) (b[i + 8] ^ mask[i % 4]);
				}
				 pushHead = new byte[4];	
				 pushHead[1] = (byte) 126;
				 pushHead[2] = (byte) (d.length >> 8);
				 pushHead[3] = (byte) (d.length & 0Xff);
				 break;
			case 127:
				d = new byte[count1 - 13];
				for (int i = 0; i < 4; ++i) {
					mask[i] = b[i + 9];
				}
				for (int i = 0; i < count1 - 13; i++) {
					d[i] = (byte) (b[i + 13] ^ mask[i % 4]);
				}
				break;
			default:
				d = new byte[count1 - 6];
				for (int i = 0; i < 4; ++i) {
					mask[i] = b[i + 2];
				}
				for (int i = 0; i < count1 - 6; i++) {
					d[i] = (byte) (b[i + 6] ^ mask[i % 4]);
				}
			    pushHead = new byte[2];
				pushHead[1] = (byte) d.length;
				break;
			}
			pushHead[0] = b[0];
			out.write(pushHead);
			out.write(d);
			System.out.println("msg=" + new String(d, "UTF-8"));
			
		}
	}
	
	private String getSecWebSocketKey(String req) {
		Pattern p = Pattern.compile("^(Sec-WebSocket-Key:).+",
				Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
		Matcher m = p.matcher(req);
		if (m.find()) {
			String foundstring = m.group();
			return foundstring.split(":")[1].trim();
		} else {
			return null;
		}

	}
	
	
	private int whichbrowser(BufferedReader in1) throws IOException{
		String Line="";
		while((Line=in1.readLine())!=null)
		{
			if(Line.contains("Sec-WebSocket-Key"))
			{
				Pattern p = Pattern.compile("^(Sec-WebSocket-Key:).+",
						Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
				Matcher m = p.matcher(Line);
				if (m.find()) {
					String foundstring = m.group();
					key = foundstring.split(":")[1].trim();
				}
				browser=0;
			}
			if(Line.contains("Sec-WebSocket-Key1"))
			{
				Pattern p = Pattern.compile("^(Sec-WebSocket-Key1:).+",
						Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
				Matcher m = p.matcher(Line);
				if (m.find()) {
					String foundstring = m.group();
					key1= foundstring.split(":")[1].trim();
				}
				browser=1;
			}
			if(Line.contains("Sec-WebSocket-Key2"))
			{
				Pattern p = Pattern.compile("^(Sec-WebSocket-Key2:).+",
						Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
				Matcher m = p.matcher(Line);
				if (m.find()) {
					String foundstring = m.group();
					key2= foundstring.split(":")[1].trim();
				}
				browser=1;
			}
			System.out.println(Line);
			if(Line.equals("")) return browser;
		}
		return browser;
	}

	private String getSecWebSocketAccept(String key) {
		String guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		key += guid;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(key.getBytes("iso-8859-1"), 0, key.length());
			byte[] sha1Hash = md.digest();
			key = base64Encode(sha1Hash);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return key;
	}

	public String base64Encode(byte[] input) {
		BASE64Encoder encoder = new BASE64Encoder();
		String base64 = encoder.encode(input);
		return base64;
	}

	public byte[] createChallenge(String key1, String key2, byte[] key3)
			throws InvalidDataException {
		byte[] part1 = getPart(key1);
		byte[] part2 = getPart(key2);
		byte[] challenge = new byte[16];
		challenge[0] = part1[0];
		challenge[1] = part1[1];
		challenge[2] = part1[2];
		challenge[3] = part1[3];
		challenge[4] = part2[0];
		challenge[5] = part2[1];
		challenge[6] = part2[2];
		challenge[7] = part2[3];
		challenge[8] = key3[0];
		challenge[9] = key3[1];
		challenge[10] = key3[2];
		challenge[11] = key3[3];
		challenge[12] = key3[4];
		challenge[13] = key3[5];
		challenge[14] = key3[6];
		challenge[15] = key3[7];
		MessageDigest md5;
		try {
			md5 = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		byte[] temp=new byte[16];
		temp = md5.digest(challenge);
//		System.out.println("****************************16byte:");
//		System.out.println(byte2hex(temp));
		return temp;
	}

	private byte[] getPart(String key) throws InvalidDataException {
		try {
			long keyNumber = Long.parseLong(key.replaceAll("[^0-9]", ""));
			long keySpace = key.split("\u0020").length - 1;
			if (keySpace == 0) {
				throw new InvalidDataException(
						"invalid Sec-WebSocket-Key (/key2/)");
			}
			long part = new Long(keyNumber / keySpace);
			return new byte[] { (byte) (part >> 24),
					(byte) ((part << 8) >> 24), (byte) ((part << 16) >> 24),
					(byte) ((part << 24) >> 24) };
		} catch (NumberFormatException e) {
			throw new InvalidDataException(
					"invalid Sec-WebSocket-Key (/key1/ or /key2/)");
		}
	}
	
	  
    public String byte2hex(byte[] b) { //һ���ֽڵ�����

        // ת��16�����ַ���

        String hs = "";
        String tmp = "";
        for (int n = 0; n < b.length; n++) {
            //����ת��ʮ�����Ʊ�ʾ

            tmp = (java.lang.Integer.toHexString(b[n] & 0XFF));
            if (tmp.length() == 1) {
                hs = hs + "0" + tmp;
            } else {
                hs = hs + tmp;
            }
        }
        tmp = null;
        return hs.toUpperCase(); //ת�ɴ�д

    }
    
    
}
}
