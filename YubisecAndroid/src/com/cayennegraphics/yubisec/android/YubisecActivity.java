/*
 * (c) 2015 Razvan Dragomirescu (Cayenne Graphics SRL)
 * #YubiKing 2015 hackathon by Yubico - https://www.yubico.com/yubiking/
 */


package com.cayennegraphics.yubisec.android;

import java.io.IOException;

import com.cayennegraphics.yubisec.android.R;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;

public class YubisecActivity extends Activity {

	public static final String TAG = "YubiOTP";

	private ProgressDialog pd;

	private boolean encryptMode = false;

	// keep track of the key index for outgoing message so that we don't reuse old keys
	// old keys are deleted anyway, so reusing one will simply result in random garbage at the other end
	private int outgoingIndex = 0;
	
	// also keep track of incoming key indexes
	// incoming messages use keys in reverse order (from the last one to the first)
	// we stop accepting outgoing messages when the two meet in the middle (outgoingIndex>=lastSeenIncomingIndex), otherwise we end up reusing a key and that's a no-no in OneTimePads
	private int lastSeenIncomingIndex = Integer.MAX_VALUE;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_yubi_otp);
		
		// fetch the outgoing and incoming key indexes from persistent storage
		outgoingIndex = getPersistentInt("OI", 0);
		lastSeenIncomingIndex = getPersistentInt("II", Integer.MAX_VALUE);
		
		// check if we haven't run out of keys
		checkIndexes();

	}

	private boolean checkIndexes() {
		if (outgoingIndex >= lastSeenIncomingIndex) {
			AlertDialog.Builder builder = new AlertDialog.Builder(
					YubisecActivity.this);

			// warn the user and exit the app
			builder.setTitle("Key pool exhausted")
					.setMessage(
							"Key pool exhausted, your Yubikey Neo needs to be reprovisioned. Yubisec will now exit.")
					.setPositiveButton("EXIT",
							new DialogInterface.OnClickListener() {
								@Override
								public void onClick(DialogInterface dialog,
										int id) {
									YubisecActivity.this.finish();
								}
							});
			builder.create().show();
			return false;
		}
		return true;
	}

	// send the text to clipboard - not currently activated, mostly for security reasons (the user might not want the plaintext put into the clipboard)
	public void setClipboard(String text) {
		ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
		ClipData clip = ClipData.newPlainText(text, text);
		clipboard.setPrimaryClip(clip);
	}

	
	// called when a Yubikey Neo is touched to the phone
	// TODO: make sure it's a YubiKey Neo and not some other tag/card
	public void onNewIntent(Intent intent) {
		Tag tagFromIntent = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
		Log.i(TAG, "Tag is " + tagFromIntent);
		IsoDep tag = IsoDep.get(tagFromIntent);
		
		// plainText contains the outgoing plaintext on Encrypt or the incoming decrypted text on Decrypt
		EditText plainText = (EditText) findViewById(R.id.plainText);
		
		// cryptoText contains the outgoing cryptotext on Encrypt or the incoming encrypted text on Decrypt
		EditText cryptoText = (EditText) findViewById(R.id.cryptoText);
		
		// decoyText is an optional text for the Plausible Deniability feature
		// the app will calculate the OneTimePad key that makes the current cryptotext decrypt to the decoy text and write it to the Yubikey
		// future attempts to decrypt this text will result in the decoy string, not the actual (real) plaintext
		// see http://nullprogram.com/blog/2008/07/11/ for details
		EditText decoyText = (EditText) findViewById(R.id.decoyText);
		String dt = decoyText.getText().toString();

		if (encryptMode) {
			// we're encrypting
			String pt = plainText.getText().toString();

			byte[] bpt = pt.getBytes();
			
			
			
			try {
				// first connect to the Yubikey Neo
				tag.connect();
				
				// some operations (like randomness generation) take a long time, so tell the NfcAdapter to wait up to 10 seconds
				tag.setTimeout(10000);
				
				// select the Yubisec app on the card based on AID
				byte[] apdu = HexUtils.toBytes("00A4040007797562696F747000");
				tag.transceive(apdu);
				
				// ok, now we fetch the key from the card (based on the current index)
				byte[] command = { (byte) 0x00, (byte) 0x04, (byte) 0x00,
						(byte) outgoingIndex, (byte) 0x00 };
				
				byte[] key = tag.transceive(command);
				Log.i(TAG, "Key is " + key.length + " " + HexUtils.toHex(key));
				// the key is automatically replaced with randomness as soon as it is read, so if you're not using the decoy functionality, future attempts to decrypt this message will result in garbage
				
				// now we try to encrypt this message
				// each message is 1 byte length + 119 bytes content, then BASE64-encoded as a 160 character ASCII message (the size of an SMS)
				byte[] crypto = new byte[120];
				crypto[0] = (byte) outgoingIndex;
				outgoingIndex++;
				// save the outgoing index so that we don't overlap incoming messages or reuse a key
				setPersistentInt("OI", outgoingIndex);

				// now XOR the text with the key - that's all there is to OneTimePad, it's plain XOR, but with a random key
				System.arraycopy(bpt, 0, crypto, 1, bpt.length);
				for (int i = 1; i < 120; i++) {
					crypto[i] ^= key[i - 1];
				}
				
				// encode it as BASE64...
				String b64 = Base64.encodeToString(crypto, Base64.NO_WRAP);
				
				// ... and show it on screen
				cryptoText.setText(b64);

				// now clear the key - this is not strictly necessary (since the key is already random), but it makes it harder for a rogue key to determine if we're just reprovisioning it or just erasing a single key
				command[1] = (byte) 0x01;
				byte[] newKey = tag.transceive(command);

				// if the user has entered e decoy text, calculate the key that would make this cryptotext decrypt as the decoy
				if (!"".equals(dt)) {
					byte[] bdt = dt.getBytes();
					for (int i = 0; i < newKey.length - 2; i++) {
						newKey[i] ^= bpt[i];
						newKey[i] ^= key[i];
						newKey[i] ^= (i < bdt.length) ? bdt[i] : 0;
					}
					byte[] newCommand = new byte[key.length + 3];
					System.arraycopy(command, 0, newCommand, 0, command.length);
					newCommand[1] = (byte) 0x02;
					newCommand[4] = (byte) (newKey.length - 2);
					System.arraycopy(newKey, 0, newCommand, 5,
							newKey.length - 2);
					
					// we now send the decoy key to the card and it will overwrite the current (random) key
					// if an attacker tries to decrypt this later, he will get your decoy message, so if someone is forcing you to give up your keys you can claim that's all you were sending
					tag.transceive(newCommand);
				}

			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
		} else {
			
			// we decrypt
			String ct = cryptoText.getText().toString();

			byte[] bct = Base64.decode(ct, Base64.NO_WRAP);
			int pos = bct[0] & 0xFF;

			try {
				// connect to the tag and indicate we're willing to wait a little longer for the reply
				tag.connect();
				tag.setTimeout(10000);
				
				// select the app on card
				byte[] apdu = HexUtils.toBytes("00A4040007797562696F747000");
				tag.transceive(apdu);

				
				// see how many keys the card can store - this is important because incoming messages start from the end of the key list, not from the start
				byte[] getMaxMessages = HexUtils.toBytes("0003000000");
				byte[] maxMessagesResponse = tag.transceive(getMaxMessages);
				int maxMessages = maxMessagesResponse[1] & 0xFF;
				
				// determine the actual position on _our_ card of the key to use
				pos = maxMessages - 1 - pos;
				setPersistentInt("II", pos);
				
				// fetch the current key from the card (it will once again be replaced with randomness)
				byte[] command = { (byte) 0x00, (byte) 0x04, (byte) 0x00,
						(byte) pos, (byte) 0x00 };
				byte[] key = tag.transceive(command);
				
				Log.i(TAG, "Key is " + key.length + " " + HexUtils.toHex(key));
				
				// each encrypted message decrypts to a 119 byte plaintext
				byte[] crypto = new byte[119];
				System.arraycopy(bct, 1, crypto, 0, bct.length - 1);
				for (int i = 0; i < 119; i++) {
					crypto[i] ^= key[i];
				}
				
				// show the plaintext in the field on the screen
				plainText.setText(new String(crypto));

				// now clear the key
				command[1] = (byte) 0x01;
				byte[] newKey = tag.transceive(command);

				// if a decoy has been used, calculate the key that will decrypt to this decoy and store it on card
				if (!"".equals(dt)) {
					byte[] bdt = dt.getBytes();
					for (int i = 0; i < newKey.length - 2; i++) {
						newKey[i] ^= bct[i + 1];
						newKey[i] ^= (i < bdt.length) ? bdt[i] : 0;
					}
					byte[] newCommand = new byte[newKey.length + 3];
					System.arraycopy(command, 0, newCommand, 0, command.length);
					newCommand[1] = (byte) 0x02;
					newCommand[4] = (byte) (newKey.length - 2);
					System.arraycopy(newKey, 0, newCommand, 5,
							newKey.length - 2);
					tag.transceive(newCommand);
				}

			} catch (IOException ioe) {
				ioe.printStackTrace();
			}

		}

		if (pd != null)
			pd.dismiss();
	}

	

	

	public void onResume() {
		super.onResume();
		PendingIntent pendingIntent = PendingIntent.getActivity(this, 0,
				new Intent(this, getClass())
						.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
		NfcAdapter.getDefaultAdapter(this).enableForegroundDispatch(this,
				pendingIntent, null, null);
	}

	public void onPause() {
		super.onPause();
		NfcAdapter.getDefaultAdapter(this).disableForegroundDispatch(this);
	}

	public void doEncrypt(View view) {
		if (checkIndexes()) {
			encryptMode = true;
			pd = ProgressDialog.show(this, "Please wait",
					"Touch the YubiKey Neo to your phone to decrypt");
		}
	}

	public void doDecrypt(View view) {
		encryptMode = false;
		pd = ProgressDialog.show(this, "Please wait",
				"Touch the YubiKey Neo to your phone to encrypt");
	}

	// store a persistent value
	private void setPersistentString(String key, String value) {
		SharedPreferences sp = getSharedPreferences("YUBISEC", 0);
		SharedPreferences.Editor ed = sp.edit();
		ed.putString(key, value);
		ed.commit();
	}

	private void setPersistentInt(String key, int value) {
		SharedPreferences sp = getSharedPreferences("YUBISEC", 0);
		SharedPreferences.Editor ed = sp.edit();
		ed.putInt(key, value);
		ed.commit();
	}

	// fetch a value from persistent storage
	private String getPersistentString(String key) {
		SharedPreferences sp = getSharedPreferences("YUBISEC", 0);
		return sp.getString(key, "");
	}

	// fetch a value from persistent storage
	private int getPersistentInt(String key, int def) {
		SharedPreferences sp = getSharedPreferences("YUBISEC", 0);
		return sp.getInt(key, def);
	}

}
