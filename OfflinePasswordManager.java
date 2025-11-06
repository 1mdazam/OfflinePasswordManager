import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Offline Password Manager
 * Stores credentials locally in an encrypted .dat file using AES + PBKDF2.
 * Author: Mohammed Azam
 */
public class OfflinePasswordManager {
    private static final String MAGIC = "OPM1";
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 16;
    private static final int ITERATIONS = 100_000;
    private static final int KEY_LEN_BITS = 256;
    private static final String FILE_NAME = "passwordstore.dat";

    static class Entry implements Serializable {
        String site, username, password, notes;
        Entry(String s, String u, String p, String n) {
            site = s; username = u; password = p; notes = n;
        }
        public String toString() {
            return "Site: " + site + "\nUsername: " + username + "\nPassword: " + password +
                   (notes.isEmpty() ? "" : "\nNotes: " + notes);
        }
    }

    private List<Entry> entries = new ArrayList<>();

    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LEN_BITS);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] encrypt(byte[] plain, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(plain);
    }

    private static byte[] decrypt(byte[] cipherData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherData);
    }

    private static byte[] serialize(List<Entry> list) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bos)) { out.writeObject(list); }
        return bos.toByteArray();
    }

    @SuppressWarnings("unchecked")
    private static List<Entry> deserialize(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        try (ObjectInputStream in = new ObjectInputStream(bis)) {
            return (List<Entry>) in.readObject();
        }
    }

    private static void save(File file, List<Entry> list, char[] master) throws Exception {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[SALT_LEN];
        byte[] iv = new byte[IV_LEN];
        sr.nextBytes(salt); sr.nextBytes(iv);
        SecretKey key = deriveKey(master, salt);
        byte[] plain = serialize(list);
        byte[] cipher = encrypt(plain, key, iv);

        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(MAGIC.getBytes(StandardCharsets.UTF_8));
            fos.write(ByteBuffer.allocate(4).putInt(salt.length).array());
            fos.write(salt);
            fos.write(ByteBuffer.allocate(4).putInt(iv.length).array());
            fos.write(iv);
            fos.write(ByteBuffer.allocate(4).putInt(cipher.length).array());
            fos.write(cipher);
        }
    }

    private static List<Entry> load(File file, char[] master) throws Exception {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] magic = fis.readNBytes(4);
            if (!MAGIC.equals(new String(magic))) throw new IOException("Invalid file");
            int saltLen = ByteBuffer.wrap(fis.readNBytes(4)).getInt();
            byte[] salt = fis.readNBytes(saltLen);
            int ivLen = ByteBuffer.wrap(fis.readNBytes(4)).getInt();
            byte[] iv = fis.readNBytes(ivLen);
            int cipherLen = ByteBuffer.wrap(fis.readNBytes(4)).getInt();
            byte[] cipher = fis.readNBytes(cipherLen);

            SecretKey key = deriveKey(master, salt);
            byte[] plain = decrypt(cipher, key, iv);
            return deserialize(plain);
        }
    }

    private void add(Scanner sc) {
        System.out.print("Site: "); String site = sc.nextLine().trim();
        System.out.print("Username: "); String u = sc.nextLine().trim();
        System.out.print("Password: "); String p = sc.nextLine().trim();
        System.out.print("Notes: "); String n = sc.nextLine().trim();
        entries.add(new Entry(site, u, p, n));
        System.out.println("Added successfully!");
    }

    private void list() {
        if (entries.isEmpty()) { System.out.println("[No entries]"); return; }
        int i = 1;
        for (Entry e : entries) System.out.println(i++ + ". " + e.site);
    }

    private void find(Scanner sc) {
        System.out.print("Enter site name or keyword: ");
        String q = sc.nextLine().toLowerCase();
        List<Entry> found = entries.stream()
            .filter(e -> e.site.toLowerCase().contains(q))
            .collect(Collectors.toList());
        if (found.isEmpty()) System.out.println("No matches found.");
        else found.forEach(e -> { System.out.println("----"); System.out.println(e); });
    }

    private void delete(Scanner sc) {
        list();
        System.out.print("Enter index to delete (0 to cancel): ");
        int idx = Integer.parseInt(sc.nextLine());
        if (idx > 0 && idx <= entries.size()) {
            entries.remove(idx - 1);
            System.out.println("Deleted successfully.");
        } else System.out.println("Cancelled or invalid.");
    }

    private void menu() {
        Scanner sc = new Scanner(System.in);
        File file = new File(FILE_NAME);
        char[] master;
        try {
            if (file.exists()) {
                System.out.print("Enter master password: ");
                master = sc.nextLine().toCharArray();
                entries = load(file, master);
                System.out.println("Loaded " + entries.size() + " entries.");
            } else {
                System.out.print("Create master password: ");
                master = sc.nextLine().toCharArray();
                save(file, entries, master);
                System.out.println("New store created!");
            }

            boolean run = true;
            while (run) {
                System.out.println("\nMenu: 1) Add  2) List  3) Find  4) Delete  5) Save & Exit  6) Exit");
                System.out.print("Choice: ");
                switch (sc.nextLine()) {
                    case "1" -> add(sc);
                    case "2" -> list();
                    case "3" -> find(sc);
                    case "4" -> delete(sc);
                    case "5" -> { save(file, entries, master); System.out.println("Saved."); run = false; }
                    case "6" -> { run = false; System.out.println("Exited without saving."); }
                    default -> System.out.println("Invalid choice.");
                }
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        new OfflinePasswordManager().menu();
    }
}
