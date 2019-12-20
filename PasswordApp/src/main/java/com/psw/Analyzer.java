package com.psw;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;

import org.apache.log4j.Logger;
import org.mindrot.jbcrypt.BCrypt;

public class Analyzer {

	// initialize the logger
	static Logger logger = Logger.getLogger(Logger.class.getClass());

	public static void main(String[] args) {

		String input = "";

		boolean infiniteLoop = true;

		// Putting an infinite loop to keep validating

		while (infiniteLoop) {

			System.out.print("Please Input a Password to Validate \n");
			System.out.print("Enter exit to quit \n");
			Scanner scanner = new Scanner(System.in);
			input = scanner.nextLine();

			// exit condition
			if (input.equalsIgnoreCase("exit")) {

				scanner.close();
				System.out.print("Bye for now \n");
				System.out.print("--------------");
				System.exit(0);
			}

			// Basic validation for number of characters, number and uppercase
			boolean valid = validatePassword(input);

			if (valid) {

				try {

					boolean pwned = checkPasswordWithAPI(input);

					if (!pwned) {

						// BCrypt
						String bCryptedPsw = BCrypt.hashpw(input, BCrypt.gensalt());
						logger.info("Bcrypted password " + bCryptedPsw);
						writeContentToFile(bCryptedPsw);
						System.out.println("Password Saved !!!");
					} else {
						System.out.println("Sorry your password has been Pwned");
					}

				} catch (IOException | NoSuchAlgorithmException e) {

					logger.fatal(e.getMessage(), e);

				}

			}

		}

	}

	/**
	 *
	 * 
	 * 
	 * @param input
	 * 
	 * @return
	 * 
	 */

	private static boolean validatePassword(String input) {

		// digit (?=.*[0-9])
		// letters (?=.*[a-zA-Z])
		// upper case (?=.*[A-Z])
		// length - 12 min no ma .{12,}

		boolean valid = false;
		Pattern p = Pattern.compile("^(?=.*[0-9])(?=.*[a-zA-Z])(?=.*[A-Z]).{12,}$");
		Matcher m = p.matcher(input);

		if (m.find()) {
			logger.info("input  " + input);
			logger.info("Password is valid: " + input);
			valid = true;
		}

		else {

			System.out.println("Not a valid password: " + input);
			System.out.println(
					"Please include atleast one letter, One Uppercase, one number and atleast 12 character long");
		}

		return valid;

	}

	private static boolean checkPasswordWithAPI(String input) throws NoSuchAlgorithmException, IOException {

		boolean isPwned = false;

		// convert to SHA1
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		digest.reset();
		digest.update(input.getBytes("utf8"));

		String sha1 = String.format("%040x", new BigInteger(1, digest.digest()));

		// Make an API call to pwned
		URL url = new URL("https://api.pwnedpasswords.com/range/" + sha1.substring(0, 5));
		logger.info("First 5 of SHA1 " + sha1.substring(0, 5));
		logger.info("SHA1 " + sha1);
		HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
		conn.setRequestMethod("GET");
		conn.setRequestProperty("Accept", "application/json");
		conn.connect();

		if (conn.getResponseCode() != 200) {
			logger.error("Did not get 200, throwing exeption ");
			throw new RuntimeException("Error Code : " + conn.getResponseCode());
		}

		BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
		String output;
		logger.info("Response from Pwned .... \n");

		// process output
		int i = 1;
		while ((output = br.readLine()) != null) {
			logger.info(i + " " + output);
			// this means password found inpwned
			// crop output to :
			output = output.substring(0, output.indexOf(":"));
			// crop sha1 to 5 char onwards
			if (output.equalsIgnoreCase(sha1.substring(5, sha1.length()))) {
				isPwned = true;
			}
			i++;
		}

		conn.disconnect();
		return isPwned;

	}

	// Method to append to file - if file does not exist create it.
	private static void writeContentToFile(String bCryptedPsw) throws IOException {

		File file = new File("../Password.txt");
		FileWriter fr = new FileWriter(file, true);
		BufferedWriter br = new BufferedWriter(fr);
		PrintWriter pr = new PrintWriter(br);
		pr.println(bCryptedPsw);
		pr.close();
		br.close();
		fr.close();

	}

}
