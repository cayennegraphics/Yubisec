/*
 * (c) 2015 Razvan Dragomirescu (Cayenne Graphics SRL)
 * #YubiKing 2015 hackathon by Yubico - https://www.yubico.com/yubiking/
 */

package com.cayennegraphics.yubisec.admin;

import java.security.SecureRandom;
import java.util.List;
import javax.smartcardio.*;

public class YubisecAdmin {

	// this class is a simple Java-based command line tool that handles the
	// initial key provisioning
	// it asks both cards to generate random keys and generates a third random
	// stream itself
	// the three streams are XOR-ed together into a single stream that is sent
	// to both cards

	public static void main(String[] args) {
		try {
			// Display the list of terminals
			TerminalFactory factory = TerminalFactory.getDefault();
			List<CardTerminal> terminals = factory.terminals().list();
			System.out.println("YubiTerminals: " + terminals);

			SecureRandom random = new SecureRandom();
			byte[] randomBytes = new byte[119];

			// we're going to talk to both cards simultaneously
			CardTerminal yubikey1 = null;
			CardTerminal yubikey2 = null;

			for (int i = 0; i < terminals.size(); i++) {
				CardTerminal xterminal = terminals.get(i);
				System.out.println("TESTING: " + xterminal.getName());
				if (xterminal.getName().equals("Yubico Yubikey NEO CCID 0")) {
					yubikey1 = xterminal;
				} else if (xterminal.getName().equals(
						"Yubico Yubikey NEO CCID 1")) {
					yubikey2 = xterminal;
				}

			}

			System.out.println("YUBIKEY1=" + yubikey1 + "\n");
			System.out.println("YUBIKEY2=" + yubikey2 + "\n");

			Card yk1 = yubikey1.connect("*");
			CardChannel ccyk1 = yk1.getBasicChannel();
			Card yk2 = yubikey2.connect("*");
			CardChannel ccyk2 = yk2.getBasicChannel();

			System.out.println("Selecting YUBIOTP ...");
			byte[] apdu = HexUtils.toBytes("00A4040007797562696F747000");

			ResponseAPDU answer1 = ccyk1.transmit(new CommandAPDU(apdu));
			System.out.println("answer1: " + answer1.toString());

			ResponseAPDU answer2 = ccyk2.transmit(new CommandAPDU(apdu));
			System.out.println("answer2: " + answer2.toString());

			// ok, first make sure the cards agree on the max number of messages

			byte[] getMaxMessages = HexUtils.toBytes("0003000000");

			answer1 = ccyk1.transmit(new CommandAPDU(getMaxMessages));
			byte[] adata1 = answer1.getData();
			// System.out.println("YK1 has replied "+HexUtils.toHex(adata1));
			short ml1 = getShort(adata1);

			answer2 = ccyk2.transmit(new CommandAPDU(getMaxMessages));
			byte[] adata2 = answer1.getData();
			// System.out.println("YK2 has replied "+HexUtils.toHex(adata2));
			short ml2 = getShort(adata2);

			System.out.println("YK1 expects " + ml1 + " max messages");
			System.out.println("YK2 expects " + ml2 + " max messages");
			if (ml1 != ml2) {
				System.out
						.println("The two cards disagree on the max number of messages, giving up");
				return;
			}

			for (int i = 0; i < ml1; i++) {
				System.out.println("Generating chunk " + i);
				String s1 = HexUtils.toHex((byte) i);
				String s2 = HexUtils.toHex((byte) (ml1 - 1 - i));
				// first we ask both cards to generate a key
				apdu = HexUtils.toBytes("000100" + s1 + "00");
				System.out.println("Asking YK1 to generate randomness at step "
						+ i + "...");
				answer1 = ccyk1.transmit(new CommandAPDU(apdu));
				adata1 = answer1.getData();

				System.out.println("Asking YK2 to generate randomness at step "
						+ i + "...");
				apdu = HexUtils.toBytes("000100" + s2 + "00");
				answer2 = ccyk2.transmit(new CommandAPDU(apdu));
				adata2 = answer2.getData();

				System.out
						.println("Asking local computer to generate randomness at step "
								+ i + "...");
				// now we generate some randomness of our own
				random.nextBytes(randomBytes);

				// XOR the streams with the local key
				for (int x = 0; x < 119; x++) {
					adata1[x] ^= randomBytes[x];
					adata2[x] ^= randomBytes[x];
				}

				// and now we ship them back to the cards

				System.out
						.println("Asking YK1 to XOR data with randomness at step "
								+ i + "...");
				apdu = HexUtils.toBytes("000200" + s1 + "77"
						+ HexUtils.toHex(adata2));
				answer1 = ccyk1.transmit(new CommandAPDU(apdu));
				System.out.println("YK1 replied " + answer1.toString());

				System.out
						.println("Asking YK2 to XOR data with randomness at step "
								+ i + "...");
				apdu = HexUtils.toBytes("000200" + s2 + "77"
						+ HexUtils.toHex(adata1));
				answer2 = ccyk2.transmit(new CommandAPDU(apdu));
				System.out.println("YK2 replied " + answer2.toString());

			}

			// commented section below can be used to test if the key generation
			// worked (by reading the keys)
			// however this destroys the keys (replaces them with randomness) so
			// don't enable this in production
			/*
			 * System.out.println("Now let's verify it ..."); for (int
			 * i=0;i<ml1;i++) { System.out.println("Verifying chunk "+i); String
			 * s1 = HexUtils.toHex((byte)i); String s2 =
			 * HexUtils.toHex((byte)(ml1-1-i)); // first we ask both cards to
			 * generate a key apdu = HexUtils .toBytes("000400"+s1+"00");
			 * System.
			 * out.println("Asking YK1 to show and destroy key at step "+i
			 * +"..."); answer1 = ccyk1.transmit(new CommandAPDU(apdu)); adata1
			 * = answer1.getData();
			 * 
			 * System.out.println("Asking YK2 to show and destroy key at step "+i
			 * +"..."); apdu = HexUtils .toBytes("000400"+s2+"00"); answer2 =
			 * ccyk2.transmit(new CommandAPDU(apdu)); adata2 =
			 * answer2.getData();
			 * 
			 * String ha1 = HexUtils.toHex(adata1); String ha2 =
			 * HexUtils.toHex(adata2); if (ha1.equals(ha2)) {
			 * System.out.println("Chunk "+i+" VERIFIED");
			 * System.out.println("Random key at step "+i+" is "+ha1); } else {
			 * System.out.println("Chunk "+i+" FAILED!!!");
			 * System.out.println(ha1 +" != "+ha2); }
			 * 
			 * }
			 * 
			 * System.out.println("Now let's verify it again, it should fail...")
			 * ; for (int i=0;i<ml1;i++) {
			 * System.out.println("Verifying chunk "+i); String s1 =
			 * HexUtils.toHex((byte)i); String s2 =
			 * HexUtils.toHex((byte)(ml1-1-i)); // first we ask both cards to
			 * generate a key apdu = HexUtils .toBytes("000400"+s1+"00");
			 * System.
			 * out.println("Asking YK1 to show and destroy key at step "+i
			 * +"..."); answer1 = ccyk1.transmit(new CommandAPDU(apdu)); adata1
			 * = answer1.getData();
			 * 
			 * System.out.println("Asking YK2 to show and destroy key at step "+i
			 * +"..."); apdu = HexUtils .toBytes("000400"+s2+"00"); answer2 =
			 * ccyk2.transmit(new CommandAPDU(apdu)); adata2 =
			 * answer2.getData();
			 * 
			 * String ha1 = HexUtils.toHex(adata1); String ha2 =
			 * HexUtils.toHex(adata2); if (ha1.equals(ha2)) {
			 * System.out.println("Chunk "+i+" VERIFIED");
			 * System.out.println("Random key at step "+i+" is "+ha1); } else {
			 * System.out.println("Chunk "+i+" FAILED!!!");
			 * System.out.println(ha1 +" != "+ha2); }
			 * 
			 * }
			 */
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Ouch: " + e.toString());
		}
	}

	public static short getShort(byte[] range) {
		return (short) ((range[0] << 8) + (range[1] & 0xff));
	}

}
