package br.com.gdc_assina;

import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.ExternalBlankSignatureContainer;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignatureContainer;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GdcAssina {
	public static final String DEST = "d:\\";

	public static String SRC = "d:\\PDFA-DECRETO.pdf";

	public static String TEMP = "z_temp";

	public static String DATATEMP = "00";

	public static String KEYSTORE = "d:\\iparv.pfx";

	public static String TEXTO = "TEXTO";

	public static String DATA_ASSINATURA = "DATA";

	public static char[] PASSWORD = "170179".toCharArray();

	public static String SAIDA = "d:\\hello_empty_sig.pdf";

	public static String IMAGE_PATH = "selo_okdocs.png";

	public static String POSICAO = "1";

	public static float MARGEM = 10.0F;

	public static void main(String[] args) throws IOException, GeneralSecurityException {
		SRC = args[0];
		SAIDA = args[1];
		KEYSTORE = args[2];
		PASSWORD = args[3].toCharArray();
		TEXTO = args[4];
		POSICAO = args[5];
		String str1;
		switch ((str1 = POSICAO).hashCode()) {
		case 49:
			if (str1.equals("1")) {
				MARGEM = 10.0F;
				break;
			}
		case 50:
			if (str1.equals("2")) {
				MARGEM = 131.0F;
				break;
			}
		case 51:
			if (str1.equals("3")) {
				MARGEM = 252.0F;
				break;
			}
		case 52:
			if (str1.equals("4")) {
				MARGEM = 373.0F;
				break;
			}
		default:
			MARGEM = 10.0F;
			break;
		}
		SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss z");
		DATA_ASSINATURA = dateFormat.format(new Date());
		Random random = new Random();
		char RANDOMICO = (char) (random.nextInt(26) + 97);
		SimpleDateFormat dateFormatname = new SimpleDateFormat("ddMMyyyyHHmmssS");
		DATATEMP = dateFormatname.format(new Date());
		TEMP = String.valueOf(TEMP) + "_" + DATATEMP + RANDOMICO + ".pdf";
		BouncyCastleProvider providerBC = new BouncyCastleProvider();
		Security.addProvider((Provider) providerBC);
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(KEYSTORE), PASSWORD);
		String alias = ks.aliases().nextElement();
		Certificate[] chain = ks.getCertificateChain(alias);
		PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
		GdcAssina app = new GdcAssina();
		app.emptySignature(SRC, TEMP, "Signature" + POSICAO, chain, MARGEM);
		app.createSignature(TEMP, SAIDA, "Signature" + POSICAO, pk, chain);
	}

	public void emptySignature(String src, String dest, String fieldname, Certificate[] chain, float MARGEM2)
			throws IOException, GeneralSecurityException {
		PdfReader reader = new PdfReader(src);
		PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());
		ImageData clientSignatureImage = ImageDataFactory.create(IMAGE_PATH);
		PdfSignatureAppearance appearance = signer.getSignatureAppearance();
		appearance.setPageRect(new Rectangle(MARGEM2, 10.0F, 120.0F, 33.0F)).setLayer2FontSize(6.0F)
				.setLayer2Text("Assinado digitalmente por:\n" + TEXTO + "\n" + DATA_ASSINATURA)
				.setImage(clientSignatureImage).setImageScale(0.0F).setPageNumber(1).setCertificate(chain[0]);
		signer.setFieldName(fieldname);
		ExternalBlankSignatureContainer externalBlankSignatureContainer = new ExternalBlankSignatureContainer(
				PdfName.Adobe_PPKLite, PdfName.ETSI_CAdES_DETACHED);
		signer.signExternalContainer((IExternalSignatureContainer) externalBlankSignatureContainer, 8192);
	}

	public void createSignature(String src, String dest, String fieldName, PrivateKey pk, Certificate[] chain)
			throws IOException, GeneralSecurityException {
		PdfReader reader = new PdfReader(src);
		Exception exception1 = null, exception2 = null;
	}

	class MyExternalSignatureContainer implements IExternalSignatureContainer {
		protected PrivateKey pk;

		protected Certificate[] chain;

		public MyExternalSignatureContainer(PrivateKey pk, Certificate[] chain) {
			this.pk = pk;
			this.chain = chain;
		}

		public byte[] sign(InputStream is) throws GeneralSecurityException {
			try {
				PrivateKeySignature signature = new PrivateKeySignature(this.pk, "SHA256", "BC");
				String hashAlgorithm = signature.getHashAlgorithm();
				BouncyCastleDigest digest = new BouncyCastleDigest();
				PdfPKCS7 sgn = new PdfPKCS7(null, this.chain, hashAlgorithm, null, (IExternalDigest) digest, false);
				byte[] hash = DigestAlgorithms.digest(is, digest.getMessageDigest(hashAlgorithm));
				byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, PdfSigner.CryptoStandard.CADES, null, null);
				byte[] extSignature = signature.sign(sh);
				sgn.setExternalDigest(extSignature, null, signature.getEncryptionAlgorithm());
				return sgn.getEncodedPKCS7(hash, PdfSigner.CryptoStandard.CADES, null, null, null);
			} catch (IOException ioe) {
				throw new RuntimeException(ioe);
			}
		}

		public void modifySigningDictionary(PdfDictionary signDic) {
		}
	}
}
