Endecode - The All-in-One Encoder/Decoder Desktop App

Features :

Endecode isn’t just another string manipulator. It’s a full-blown, button-clicking, format-hopping, webcam-peeking bundle of encoding joy:

Morse Code
↳ Encode plain text to Morse code and decode it back using a custom JSON map.

DES Encryption
↳ Encrypt sensitive text using the Data Encryption Standard (DES) algorithm.
↳ Key saved locally (des.key) because you love living on the edge.
↳ Decrypt encrypted strings using the saved key.

ASCII Translator
↳ Convert characters to their ASCII numerical values.
↳ Bring 'em back from numeric oblivion to readable text.

QR Code Generator & Scanner
↳ Generate QR codes for any text.
↳ Scan QR codes live using your webcam like it's 2012 again.
↳ No need to press 40 keys—just one labeled “Scan QR”.

 Technologies Used
- Java Swing – The UI that time forgot.
- ZXing ("Zebra Crossing") – QR code generation and scanning.
- Sarxos Webcam Capture API – For webcam access without the usual system sacrifice.
- Google Gson – Because we love our JSON readable and light.
- Java Cryptography Extension (JCE) – For DES encryption/decryption.

Note : 
The des.key file stores the DES (Data Encryption Standard) secret key used for encryption and decryption in the DES Code module of the Endecode application.
It's a base64-encoded binary file containing the DES secret key.It's generated automatically the first time you run DES encryption and loaded whenever DES decryption is requested.
Don’t delete des.key unless you’re into irreversible loss.
For Morse decoding, ensure your code has proper spacing (. .-.. .-.. --- not .ELLO).


  You're xml file should include the following dependencies :
  
<dependency>
    <groupId>com.google.zxing</groupId>
    <artifactId>core</artifactId>
    <version>3.3.3</version>
</dependency>

<dependency>
    <groupId>com.google.zxing</groupId>
    <artifactId>javase</artifactId>
    <version>3.3.3</version>
</dependency>

   <dependency>
        <groupId>com.github.sarxos</groupId>
        <artifactId>webcam-capture</artifactId>
        <version>0.3.12</version>
    </dependency>
    <dependency>
        <groupId>com.google.zxing</groupId>
        <artifactId>core</artifactId>
        <version>3.5.0</version>
    </dependency>
    <dependency>
        <groupId>com.google.zxing</groupId>
        <artifactId>javase</artifactId>
        <version>3.5.0</version>
    </dependency>
  
  <dependency>
  <groupId>org.json</groupId>
  <artifactId>json</artifactId>
  <version>20210307</version>
</dependency>

<dependency>
    <groupId>com.google.code.gson</groupId>
    <artifactId>gson</artifactId>
    <version>2.10.1</version>
</dependency>
