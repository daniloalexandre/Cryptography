package br.ufpb.dicomflow.integrationAPI.crypto;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.Part;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Store;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEUtil;

/**
 * a simple example that reads an encrypted email.
 * <p>
 * The key store can be created using the class in
 * org.bouncycastle.jce.examples.PKCS12Example - the program expects only one
 * key to be present.
 */
public class ReadEncryptedMail
{
    public static void main(
        final String args[])
        throws Exception
    {
        if (args.length != 6)
        {
            System.err.println("usage: ReadEncryptedMail <jksKeystore> <password> <alias> <email address> <email password> <imap server> <folder>");
            System.exit(0);
        }

        //
        // Open the key store
        //
        KeyStore    ks = KeyStore.getInstance("JKS");
//        KeyStore    ks = KeyStore.getInstance("PKCS12", "BC");

        ks.load(new FileInputStream(args[0]), args[1].toCharArray());

        Enumeration e = ks.aliases();
        String      keyAlias = null;

        while (e.hasMoreElements())
        {
            String  alias = (String)e.nextElement();

            if (ks.isKeyEntry(alias))
            {
                keyAlias = alias;
            }
        }

        if (keyAlias == null)
        {
            System.err.println("can't find a private key!");
            System.exit(0);
        }

        //
        // find the certificate for the private key and generate a 
        // suitable recipient identifier.
        //
        X509Certificate cert = (X509Certificate)ks.getCertificate(keyAlias);
        RecipientId     recId = new JceKeyTransRecipientId(cert);

        //
        // Get a Session object with the default properties.
        //         
//        Properties props = System.getProperties();
        Properties props = new Properties();
        props.put("mail.imap.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
        props.put("mail.imap.socketFactory.fallback", "false");
		props.put("mail.store.protocol", "imaps");

        Session session = Session.getDefaultInstance(props, new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication()
            {
                  return new PasswordAuthentication(args[2], args[3]);
            }
       });
        
        Store store = session.getStore(/*this.provider*/);
		store.connect(args[4], null, null);

	    Folder folder = store.getFolder(args[5]);
	    
	    folder.open(Folder.READ_WRITE);
	    
	    
	    List<Message> messages = new ArrayList<Message>();
	    messages.addAll(Arrays.asList(folder.getMessages()));
	    
	    Iterator<Message> it = messages.iterator();
	    while (it.hasNext()) {
			MimeMessage message = (MimeMessage) it.next();
//			MimeMessage mimeMessage = new MimeMessage(session, message.getInputStream());
			
			SMIMEEnveloped       m = new SMIMEEnveloped(message);

	        RecipientInformationStore   recipients = m.getRecipientInfos();
	        RecipientInformation        recipient = recipients.get(recId);

//	        MimeBodyPart        res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient((PrivateKey)ks.getKey(keyAlias, null)).setProvider("BC")));
	        MimeBodyPart        res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient((PrivateKey)ks.getKey(keyAlias, args[3].toCharArray()))));
	        MimeMultipart content = (MimeMultipart) res.getContent();
	        for (int i = 0; i < content.getCount(); i++) {
	        	Part part = content.getBodyPart(i);
				// pegando um tipo do conteúdo
				String contentType = part.getContentType();

				// Tela do conteúdo
				if (contentType.toLowerCase().startsWith("text/xml")) {
					System.out.println("Message Contents");
			        System.out.println("----------------");
					System.out.println(part.getContent().toString());
				}
				
				else if(contentType.toLowerCase().startsWith("multipart/mixed")){
					MimeMultipart mixedContent = (MimeMultipart) part.getContent();
					for (int j = 0; j < mixedContent.getCount(); j++) {
						Part part2 = mixedContent.getBodyPart(j);
						// pegando um tipo do conteúdo
						String contentType2 = part2.getContentType();

						// Tela do conteúdo
						if (contentType2.toLowerCase().startsWith("text/xml")) {
							System.out.println("Message Contents");
					        System.out.println("----------------");
							System.out.println(part2.getContent().toString());
						}
					}
				}
				
				
	        }
	        
//	        System.out.println(res.getContent());
		}

//        MimeMessage msg = new MimeMessage(session, new FileInputStream("encrypted.message"));
//
//        SMIMEEnveloped       m = new SMIMEEnveloped(msg);
//
//        RecipientInformationStore   recipients = m.getRecipientInfos();
//        RecipientInformation        recipient = recipients.get(recId);
//
////        MimeBodyPart        res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient((PrivateKey)ks.getKey(keyAlias, null)).setProvider("BC")));
//        MimeBodyPart        res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient((PrivateKey)ks.getKey(keyAlias, null))));
//
//        System.out.println("Message Contents");
//        System.out.println("----------------");
//        System.out.println(res.getContent());
    }
}