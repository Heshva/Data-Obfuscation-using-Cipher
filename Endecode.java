package codes;

import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.image.BufferedImage;
import java.io.IOException;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import com.github.sarxos.webcam.Webcam;
import com.github.sarxos.webcam.WebcamPanel;
import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.io.FileReader;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;



public class Endecode extends JFrame {

    private JTextArea outputArea;
    private JLabel qrLabel;
    private static Map<String, String> morseMap = new HashMap<>();
    private static Map<String, String> reverseMorseMap = new HashMap<>();
    private static SecretKey desKey;

    public Endecode() {
        setTitle("Endecode Encoder/Decoder");
        setSize(800, 600);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));

        // Output Area
        outputArea = new JTextArea();
        outputArea.setFont(new Font("Monospaced", Font.PLAIN, 14));
        outputArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(outputArea);
        scrollPane.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Tabs
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.add("Morse Code", createMorsePanel());
        tabbedPane.add("DES Code", createDESPanel());
        tabbedPane.add("ASCII Code", createASCIIPanel());
        tabbedPane.add("QR Code", createQRPanel());

        
        add(tabbedPane, BorderLayout.CENTER);
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tabbedPane, scrollPane);
        splitPane.setResizeWeight(0.5); 
        splitPane.setDividerSize(5);
        splitPane.setBorder(null);

        
        add(splitPane, BorderLayout.CENTER);
        loadMorseCode();
        setVisible(true);
    }

    private JPanel createMorsePanel() {
        JPanel panel = new JPanel(new FlowLayout());

        JTextField inputField = new JTextField(20);
        JButton encodeBtn = new JButton("Encode");
        JButton decodeBtn = new JButton("Decode");

        encodeBtn.addActionListener(e -> {
            String input = inputField.getText().toUpperCase();
            output("Morse Encoded: " + encodeMorse(input));
        });

        decodeBtn.addActionListener(e -> {
            String input = inputField.getText();
            output("Morse Decoded: " + decodeMorse(input));
        });

        panel.add(new JLabel("Text/Morse Code:"));
        panel.add(inputField);
        panel.add(encodeBtn);
        panel.add(decodeBtn);
        return panel;
    }

    private JPanel createDESPanel() {
        JPanel panel = new JPanel(new FlowLayout());

        JTextField inputField = new JTextField(20);
        JButton encryptBtn = new JButton("Encrypt");
        JButton decryptBtn = new JButton("Decrypt");

        encryptBtn.addActionListener(e -> {
            try {
                desKey = generateDESKey();
                saveKey(desKey, "des.key");
                String encrypted = encryptDES(inputField.getText(), desKey);
                output("DES Encrypted: " + encrypted);
            } catch (Exception ex) {
                output("Error encrypting: " + ex.getMessage());
            }
        });

        decryptBtn.addActionListener(e -> {
            try {
                desKey = loadKey("des.key");
                String decrypted = decryptDES(inputField.getText(), desKey);
                output("DES Decrypted: " + decrypted);
            } catch (Exception ex) {
                output("Error decrypting: " + ex.getMessage());
            }
        });

        panel.add(new JLabel("Text:"));
        panel.add(inputField);
        panel.add(encryptBtn);
        panel.add(decryptBtn);
        return panel;
    }

    private JPanel createASCIIPanel() {
        JPanel panel = new JPanel(new FlowLayout());

        JTextField inputField = new JTextField(20);
        JButton encodeBtn = new JButton("To ASCII");
        JButton decodeBtn = new JButton("From ASCII");

        encodeBtn.addActionListener(e -> {
            StringBuilder sb = new StringBuilder();
            for (char c : inputField.getText().toCharArray()) {
                sb.append((int) c).append(" ");
            }
            output("ASCII Encoded: " + sb.toString().trim());
        });

        decodeBtn.addActionListener(e -> {
            try {
                String[] codes = inputField.getText().split(" ");
                StringBuilder sb = new StringBuilder();
                for (String code : codes) {
                    sb.append((char) Integer.parseInt(code));
                }
                output("ASCII Decoded: " + sb.toString());
            } catch (NumberFormatException ex) {
                output("Invalid ASCII input.");
            }
        });

        panel.add(new JLabel("Text/ASCII:"));
        panel.add(inputField);
        panel.add(encodeBtn);
        panel.add(decodeBtn);
        return panel;
    }
    
    private JPanel createQRPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JTextField inputField = new JTextField();
        inputField.setPreferredSize(new Dimension(300, 30));
        inputField.setMaximumSize(new Dimension(300, 30));
        inputField.setMinimumSize(new Dimension(200, 30));
        inputField.setFont(new Font("SansSerif", Font.PLAIN, 14));

        JButton generateBtn = new JButton("Generate QR");
        generateBtn.setAlignmentX(Component.CENTER_ALIGNMENT);

        JButton scanBtn = new JButton("Scan QR"); 
        scanBtn.setAlignmentX(Component.CENTER_ALIGNMENT);
        scanBtn.addActionListener(this::handleQRCodeScan); 

        qrLabel = new JLabel(); 
        qrLabel.setPreferredSize(new Dimension(200, 200));
        qrLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        generateBtn.addActionListener(e -> {
            String text = inputField.getText();
            try {
                BufferedImage qrImage = generateQRImage(text, 200, 200);
                qrLabel.setIcon(new ImageIcon(qrImage));
                output("QR code Generated");
            } catch (Exception ex) {
                output("Error generating QR code: " + ex.getMessage());
            }
        });

        panel.add(new JLabel("Text:"));
        panel.add(inputField);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        panel.add(generateBtn);
        panel.add(Box.createRigidArea(new Dimension(0, 10)));
        panel.add(scanBtn); // 🆕 Adding scan button to the panel
        panel.add(Box.createRigidArea(new Dimension(0, 10)));
        panel.add(qrLabel);

        return panel;
    }


    

    private void output(String msg) {
        outputArea.append(msg + "\n");
    }

    private void loadMorseCode() {
        try {
            Gson gson = new Gson();
            FileReader reader = new FileReader("C:/Users/heshv/codes/src/main/java/codes/morse.json");
            morseMap = gson.fromJson(reader, new TypeToken<Map<String, String>>() {}.getType());
            reader.close();

            for (Map.Entry<String, String> entry : morseMap.entrySet()) {
                reverseMorseMap.put(entry.getValue(), entry.getKey());
            }
        } catch (IOException e) {
            output("Failed to load Morse map: " + e.getMessage());
        }
    }

    private static String encodeMorse(String text) {
        StringBuilder morse = new StringBuilder();
        for (char c : text.toCharArray()) {
            morse.append(morseMap.getOrDefault(String.valueOf(c), "?")).append(" ");
        }
        return morse.toString().trim();
    }

    private static String decodeMorse(String code) {
        StringBuilder text = new StringBuilder();
        for (String symbol : code.trim().split(" ")) {
            text.append(reverseMorseMap.getOrDefault(symbol, "?"));
        }
        return text.toString();
    }

    private static SecretKey generateDESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        return keyGen.generateKey();
    }

    private static void saveKey(SecretKey key, String filePath) throws IOException {
        byte[] keyBytes = key.getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(keyBytes);
        Files.write(Paths.get(filePath), base64Key.getBytes());
    }

    private static SecretKey loadKey(String filePath) throws IOException {
        byte[] keyBytes = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(filePath)));
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, "DES");
    }

    private static String encryptDES(String text, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(text.getBytes("UTF8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptDES(String encryptedText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes, "UTF8");
    }

    private BufferedImage generateQRImage(String text, int width, int height) throws WriterException {
        QRCodeWriter writer = new QRCodeWriter();
        BitMatrix matrix = writer.encode(text, BarcodeFormat.QR_CODE, width, height);
        return MatrixToImageWriter.toBufferedImage(matrix);
    }

  

    

    public static void main(String[] args) {
    	
    	 SwingUtilities.invokeLater(Endecode::new);    	
        Scanner sc = new Scanner(System.in);

        System.out.println("1. HASH VALUE");
        System.out.println("2. MORSE CODE");
        System.out.println("3. DES CODE");
        System.out.println("4. ASCII CODE");
        System.out.println("5.  QR CODE");
        System.out.print("Enter your choice: ");
        int number = sc.nextInt();
        sc.nextLine(); 

        switch (number) {
            case 1:
                System.out.println("Hash Code");
                System.out.print("Enter the message: ");
                String hv = sc.nextLine();

                try {
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    byte[] hash = md.digest(hv.getBytes());

                    StringBuilder hex = new StringBuilder();
                    for (byte b : hash) {
                        hex.append(String.format("%02x", b));
                    }
                    System.out.println("Hashed Value (SHA-256): " + hex);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                break;

            case 2:
                System.out.println("MORSE CODE");
                System.out.println("1. Encode");
                System.out.println("2. Decode");
                System.out.print("Enter your choice: ");
                int set2 = sc.nextInt();
                sc.nextLine();
                if (set2 == 1) {
                    System.out.print("Enter the message: ");
                    String msge = sc.nextLine().toUpperCase();
                    System.out.println("Encoded Morse: " + encodeMorse(msge));
                } else if (set2 == 2) {
                    System.out.print("Enter the Morse code: ");
                    String msgd = sc.nextLine();
                    System.out.println("Decoded Text: " + decodeMorse(msgd));
                } else {
                    System.out.println("Invalid choice.");
                }
    break;       
            case 3:
            	 System.out.println("DES CODE");
                 System.out.println("1. Encode");
                 System.out.println("2. Decode");
                 System.out.print("Enter your choice: ");
                 int set3 = sc.nextInt();
                 sc.nextLine();

                 try {
                     if (desKey == null) desKey = generateDESKey();

                     if (set3 == 1) {
                         System.out.print("Enter the message: ");
                         String msg = sc.nextLine();
                         desKey = generateDESKey();
                         saveKey(desKey, "des.key");
                         String encrypted = encryptDES(msg, desKey);
                         System.out.println("Encrypted Text: " + encrypted);


                     } else if (set3 == 2) {
                         System.out.print("Enter the encrypted text: ");
                         String encText = sc.nextLine();
                         desKey = loadKey("des.key");
                         String decrypted = decryptDES(encText, desKey);
                         System.out.println("Decrypted Text: " + decrypted);


                     } else {
                         System.out.println("Invalid choice.");
                     }
                 } catch (Exception e) {
                     System.out.println("Error during DES processing: " + e.getMessage());
                 }
                break;

            case 4:
                System.out.println("ASCII VALUE");
                System.out.println("1. Encode");
                System.out.println("2. Decode");
                System.out.print("Enter your choice: ");
                int set4 = sc.nextInt();
                sc.nextLine(); // Consume newline

                if (set4 == 1) {
                    System.out.print("Enter the string: ");
                    String input = sc.nextLine();
                    Switches.stringToAscii(input);
                } else if (set4 == 2) {
                    System.out.print("Enter ASCII values (separated by space): ");
                    String asciiInput = sc.nextLine();
                    Switches.asciiToString(asciiInput);
                } else {
                    System.out.println("Invalid choice!");
                }
                break;

            case 5:
                handleQRCode(sc);
                break;

            default:
                System.out.println("Invalid choice");
        }

        sc.close();
    }

    private static void handleQRCode(Scanner sc) {
        System.out.println("1. Generate QR");
        System.out.println("2. Scan QR");
        System.out.print("Enter your choice: ");
        int choice = sc.nextInt();
        sc.nextLine(); 

        if (choice == 1) {
            System.out.print("Enter text to generate QR: ");
            String text = sc.nextLine();
            try {
                generateQRcode(text);
            } catch (WriterException | IOException e) {
                e.printStackTrace();
            }
        } else if (choice == 2) {
            scanQRCode();
        } else {
            System.out.println("Invalid choice.");
        }
    }
    
    private void handleQRCodeScan(ActionEvent e) {
        JFrame scanWindow = new JFrame("QR Code Scanner (Press 'Q' to Close)");
        scanWindow.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        Webcam webcam = Webcam.getDefault();
        webcam.setViewSize(new Dimension(640, 480));
        WebcamPanel panel = new WebcamPanel(webcam);
        panel.setFPSDisplayed(true);
        panel.setMirrored(true); 

        scanWindow.add(panel, BorderLayout.CENTER);
        scanWindow.setSize(800, 600);
        scanWindow.setLocationRelativeTo(null);
        scanWindow.setVisible(true);

        scanWindow.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyChar() == 'q' || e.getKeyChar() == 'Q') {
                    webcam.close();
                    scanWindow.dispose();
                }
            }
        });

        new Thread(() -> {
            while (webcam.isOpen()) {
                BufferedImage image = webcam.getImage();
                if (image == null) continue;

                try {
                    LuminanceSource source = new BufferedImageLuminanceSource(image);
                    BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
                    Result result = new MultiFormatReader().decode(bitmap);

                    if (result != null) {
                        String scannedText = result.getText();
                        SwingUtilities.invokeLater(() -> {
                            output("Scanned QR Code: " + scannedText);
                            JOptionPane.showMessageDialog(scanWindow, "Scanned: " + scannedText);
                            webcam.close();
                            scanWindow.dispose();
                        });
                        break;
                    }
                } catch (NotFoundException ignored) {}

                try {
                    Thread.sleep(100);
                } catch (InterruptedException ignored) {}
            }
        }).start();
    }

    private static void generateQRcode(String text) throws WriterException, IOException {
        QRCodeWriter w = new QRCodeWriter();
        BitMatrix bitMatrix = w.encode(text, BarcodeFormat.QR_CODE, 30, 30);

        for (int y = 0; y < bitMatrix.getHeight(); y++) {
            for (int x = 0; x < bitMatrix.getWidth(); x++) {
                System.out.print(bitMatrix.get(x, y) ? "██" : "  ");  
            }
            System.out.println();
        }
    }

    private static void scanQRCode() {
        System.out.println("Starting QR Code Scanner...");

        Webcam webcam = Webcam.getDefault();
        webcam.setViewSize(new Dimension(640, 480));
        WebcamPanel panel = new WebcamPanel(webcam);
        panel.setFPSDisplayed(true);

        JFrame window = new JFrame("QR Code Scanner (Press 'Q' to Close)");
        window.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        window.setLayout(new BorderLayout());
        window.add(panel, BorderLayout.CENTER);
        window.setSize(800, 600);
        window.setLocationRelativeTo(null);
        window.setVisible(true);

       
        window.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyChar() == 'q' || e.getKeyChar() == 'Q') {
                    System.out.println("Scanner closed by user.");
                    webcam.close();
                    window.dispose();
                }
            }
        });

        new Thread(() -> {
            while (webcam.isOpen()) {
                BufferedImage image = webcam.getImage();
                if (image == null) continue;

                try {
                    String qrText = readQRCode(image);
                    if (qrText != null) {
                        System.out.println("QR Code Detected: " + qrText);
                        JOptionPane.showMessageDialog(window, "QR Code: " + qrText);
                        break;
                    }
                } catch (NotFoundException ignored) {}

                try {
                    Thread.sleep(100);
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }
            }

            if (webcam.isOpen()) {
                webcam.close();
            }
            window.dispose();
        }).start();
    }



    private static String readQRCode(BufferedImage image) throws NotFoundException {
        LuminanceSource source = new BufferedImageLuminanceSource(image);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
        Result result = new MultiFormatReader().decode(bitmap);
        return result.getText();
    }
}

class Switches {
    public static void stringToAscii(String input) {
        System.out.print("ASCII values: ");
        for (int i = 0; i < input.length(); i++) {
            System.out.print((int) input.charAt(i) + " ");
        }
        System.out.println();
    }

    public static void asciiToString(String input) {
        String[] asciiValues = input.split(" ");
        StringBuilder result = new StringBuilder();

        for (String ascii : asciiValues) {
            int asciiValue = Integer.parseInt(ascii);
            result.append((char) asciiValue);
        }

        System.out.println("Converted string: " + result);
    }
}
