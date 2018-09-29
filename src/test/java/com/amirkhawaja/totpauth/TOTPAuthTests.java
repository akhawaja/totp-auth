package com.amirkhawaja.totpauth;

/*
  MIT License

  Copyright (c) 2018 Amir Khawaja

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
 */

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
