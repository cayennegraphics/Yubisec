/*
 * (c) 2015 Razvan Dragomirescu (Cayenne Graphics SRL)
 * #YubiKing 2015 hackathon by Yubico - https://www.yubico.com/yubiking/
 */

package com.cayennegraphics.yubisec;

import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;
import javacardx.apdu.ExtendedLength;


public class Yubisec extends Applet implements ExtendedLength {
	
	// otpkey will store the actual OneTimePad key that we use
	// it's a flash-based array of MAX_MESSAGES keys, MLEN bytes each
	private byte[] otpkey;
	
	
	private byte[] temp;

	// how many keys to create/store
	// currently limited to 50 to speed things up in the demo video - key generation takes a while...
	private static final short MAX_MESSAGES = 50;
	
	// length of a single key/message (119 bytes get encoded by the Android app into 1 byte length + 119 bytes cryptotext, then BASE64-encoded into 160 chars - the size of an SMS)
	private static final short MLEN = 119;
	
	// INS (instructions) supported by the app
	
	// generate 119 bytes of randomness at the current pointer
	private static final byte RANDOMIZE = (byte) 1;
	
	// XOR the key with a given byte array (this combines the randomness on this card with other external sources)
	// in this particular case, the other YubiKey Neo generates its own random stream and the phone generates yet anothe rone
	// the 3 (three) streams are XORed together to result in a common key stream
	private static final byte XOR = (byte) 2;
	
	// show a key and _immediately_ replace it with randomness to destroy it
	private static final byte SHOWANDDESTROY = (byte) 4;
	
	// simply return the maximum number of keys/messages (MAX_MESSAGES)
	private static final byte GETMAXMESSAGES = (byte) 3;
	
	RandomData rand;
	
	public Yubisec() {
		rand = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		otpkey = new byte[MAX_MESSAGES*MLEN];
		temp = JCSystem.makeTransientByteArray((short) MLEN,
				JCSystem.CLEAR_ON_DESELECT);
		
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new com.cayennegraphics.yubisec.Yubisec().register(bArray,
				(short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		short len = apdu.setIncomingAndReceive();
		short offs = apdu.getOffsetCdata();
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		byte ins = buf[ISO7816.OFFSET_INS];
		
		switch (ins) {
			
		case RANDOMIZE:
			short otpoffset = (short)(p2*MLEN);
			rand.generateData(otpkey, otpoffset, MLEN);
			apdu.setOutgoing();
			apdu.setOutgoingLength(MLEN);
			apdu.sendBytesLong(otpkey, (short)(p2*MLEN), MLEN);
			break;
			
		case XOR:
			short otpoffset1 = (short)(p2*MLEN);
			if (len<MLEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			Util.arrayCopyNonAtomic(otpkey, otpoffset1, temp, (short)0, MLEN);
			for (short i=0;i<MLEN;i++) {
				temp[i]^=buf[offs+i];
			}
			Util.arrayCopyNonAtomic(temp, (short)0, otpkey, otpoffset1, MLEN);
			
			break;
		case GETMAXMESSAGES:
			Util.setShort(buf, offs, (short)(MAX_MESSAGES));
			apdu.setOutgoingAndSend(offs, (short)2);
			break;
		case SHOWANDDESTROY:
			short otpoffset2 = (short)(p2*MLEN);
			Util.arrayCopyNonAtomic(otpkey, otpoffset2, buf, offs, MLEN);
			rand.generateData(temp, (short)0, MLEN);
			Util.arrayCopyNonAtomic(temp, (short)0, otpkey, otpoffset2, MLEN);
			apdu.setOutgoingAndSend(offs, MLEN);
			break;
			
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}