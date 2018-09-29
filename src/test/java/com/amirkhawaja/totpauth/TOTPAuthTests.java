package com.amirkhawaja.totpauth;

import com.google.zxing.WriterException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.io.File;
import java.io.IOException;

class TOTPAuthTests {

	@Test
	void testAuthenticatorUtilityGeneratesProperSecret() {
		String secretKey = AuthenticatorUtility.generateRandomSecretKey();
		Assertions.assertEquals(32, secretKey.length());

		secretKey = AuthenticatorUtility.generateRandomSecretKey(true);

		// With spaces every 4-characters, the 32-character string becomes 39-characters long
		Assertions.assertEquals(39, secretKey.length());
	}

	@Test
	void testOneTimePasswordIsWithinRange() throws InterruptedException {
		String secretKey = AuthenticatorUtility.generateRandomSecretKey();
		String totpCode = AuthenticatorUtility.generateTOTPCode(secretKey);

		Assertions.assertEquals(6, totpCode.length());

		secretKey = AuthenticatorUtility.generateRandomSecretKey();
		totpCode = AuthenticatorUtility.generateTOTPCode(secretKey, 8);

		Assertions.assertEquals(8, totpCode.length());
	}

	@Test()
	void testOneTimePasswordIsOutsideRange() throws InterruptedException {
		final String secretKey = AuthenticatorUtility.generateRandomSecretKey();
		final Executable executable = () -> AuthenticatorUtility.generateTOTPCode(secretKey, 7);

		Assertions.assertThrows(IllegalArgumentException.class, executable, "returnDigits must be either 6 or 8");
	}

	@Test
	void testQRCodeIsGenerated() throws IOException, WriterException {
		final String secretKey = AuthenticatorUtility.generateRandomSecretKey();
		final String barcodeData =
				AuthenticatorUtility.generateBarCodeData(secretKey, "user@example.com", "Example " + "Company");
		final String homeDirectory = System.getProperty("user.home") + "/Desktop";
		final String qrFile = homeDirectory + "/qr.png";

		AuthenticatorUtility.createQRCode(barcodeData, qrFile, 200, 200);

		final File file = new File(qrFile);
		Assertions.assertTrue(file.exists());

		boolean deleted = file.delete();
		Assertions.assertTrue(deleted);
	}

}
