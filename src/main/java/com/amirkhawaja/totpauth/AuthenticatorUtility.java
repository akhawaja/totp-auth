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

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import lombok.experimental.UtilityClass;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

@UtilityClass
public class AuthenticatorUtility {

	/**
	 * Generate a random secret key.
	 *
	 * @return Random secret that is 32-characters long separated by spaces every 4-characters.
	 */
	public String generateRandomSecretKey() {
		return generateRandomSecretKey(false);
	}

	/**
	 * Generate a random secret key.
	 *
	 * @param humanReadable Make the output human readable.
	 * @return Random secret that is 32-characters long separated by spaces every 4-characters.
	 */
	public String generateRandomSecretKey(final boolean humanReadable) {
		final SecureRandom random = new SecureRandom();
		final Base32 base32 = new Base32();
		final byte[] bytes = new byte[20];

		random.nextBytes(bytes);

		final String secretKey = base32.encodeToString(bytes);

		if (humanReadable) {
			return secretKey.toUpperCase().replaceAll("(.{4})(?=.{4})", "$1 ");
		}

		return secretKey.toUpperCase();
	}

	/**
	 * Generate a TOTP code.
	 *
	 * @param secretKey The 2fa secret.
	 * @return The 6-digit one-time password.
	 */
	public String generateTOTPCode(final String secretKey) {
		return generateTOTP(secretKey, 6);
	}

	/**
	 * Generate a TOTP code.
	 *
	 * @param secretKey The 2fa secret.
	 * @param returnDigits The number of digits in the TOTP.
	 * @return The 6-digit one-time password.
	 */
	public String generateTOTPCode(final String secretKey, final int returnDigits) {
		return generateTOTP(secretKey, returnDigits);
	}

	/**
	 * Create a QR code that can be used with a TOTP authenticator app.
	 *
	 * @param barCodeData The data to embed in the QR code.
	 * @param filePath The path to the PNG file representing the QR code.
	 * @param height The QR code image height.
	 * @param width The QR code image width.
	 * @throws WriterException Unable to write to the image file.
	 * @throws IOException Unable to write to the image file.
	 */
	public void createQRCode(final String barCodeData, final String filePath, final int height, final int width) throws
		WriterException, IOException {
		final BitMatrix matrix = new MultiFormatWriter().encode(barCodeData, BarcodeFormat.QR_CODE, width, height);

		try (FileOutputStream out = new FileOutputStream(filePath)) {
			MatrixToImageWriter.writeToStream(matrix, "png", out);
		}
	}

	/**
	 * Generate the data to be embedded in a barcode image.
	 *
	 * @param secretKey The secret associated with the account.
	 * @param account The account.
	 * @param issuer The issuer.
	 * @return The barcode data.
	 */
	public String generateBarCodeData(final String secretKey, final String account, final String issuer) {
		final String normalizedBase32Key = secretKey.replace(" ", "").toUpperCase();

		// Format of the output:
		// otpauth://totp/user%40domain.com?secret=RTY3WA2GHORGMD11ON7OOP6LJXSMW35F&issuer=Example%20Company
		return "otpauth://totp/" +
		       URLEncoder.encode(issuer + ":" + account, StandardCharsets.UTF_8).replace("+", "%20") + "?secret=" +
		       URLEncoder.encode(normalizedBase32Key, StandardCharsets.UTF_8).replace("+", "%20") + "&issuer=" +
		       URLEncoder.encode(issuer, StandardCharsets.UTF_8).replace("+", "%20");
	}

	/**
	 * Generate the TOTP.
	 *
	 * @param secretKey The secret of the account.
	 * @param returnDigits The number of digits in the OTP.
	 * @return The OTP.
	 */
	private String generateTOTP(final String secretKey, final int returnDigits) {
		if (returnDigits != 6 && returnDigits != 8) {
			throw new IllegalArgumentException("returnDigits must be either 6 or 8");
		}

		final String normalizedBase32Key = secretKey.replace(" ", "").toUpperCase();
		final Base32 base32 = new Base32();
		final byte[] bytes = base32.decode(normalizedBase32Key);
		final String hexKey = Hex.encodeHexString(bytes);
		final long time = (System.currentTimeMillis() / 1000) / 30;
		final String hexTime = Long.toHexString(time);

		return TOTP.generateTOTP(hexKey, hexTime, String.valueOf(returnDigits));
	}

}
