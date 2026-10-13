// Controller Spring/Servlet PROPOSITALMENTE VULNERÁVEL (corpus de teste do SAST).
package demo;

import java.io.*;
import java.security.MessageDigest;
import java.sql.*;
import java.util.Random;
import javax.crypto.Cipher;
import javax.servlet.http.*;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    private static final String DB_PASSWORD = "Pr0ducao#2026"; // EXPECT: CWE-798
    private Connection conn;

    @GetMapping("/user")
    public String user(HttpServletRequest req) throws Exception {
        String id = req.getParameter("id");
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery("SELECT * FROM users WHERE id = " + id); // EXPECT: CWE-89
        return rs.getString(1);
    }

    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        Runtime.getRuntime().exec("ping -c 1 " + host); // EXPECT: CWE-78
        return "ok";
    }

    @GetMapping("/file")
    public void file(@RequestParam String name, HttpServletResponse resp) throws Exception {
        String path = "/var/data/" + name;
        FileInputStream in = new FileInputStream(path); // EXPECT: CWE-22
        resp.getWriter().println("Arquivo: " + name); // EXPECT: CWE-79
        in.close();
    }

    @GetMapping("/go")
    public void go(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        resp.sendRedirect(req.getParameter("next")); // EXPECT: CWE-601
    }

    @PostMapping("/import")
    public Object importData(HttpServletRequest req) throws Exception {
        return new ObjectInputStream(req.getInputStream()).readObject(); // EXPECT: CWE-502
    }

    public String hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // EXPECT: CWE-327
        return new String(md.digest(password.getBytes()));
    }

    public byte[] encrypt(byte[] key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding"); // EXPECT: CWE-327
        return c.doFinal(data);
    }

    public Object parse(InputStream xml) throws Exception {
        return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xml); // EXPECT: CWE-611
    }

    public String resetToken() {
        String resetToken = Long.toString(new Random().nextLong()); // EXPECT: CWE-330
        return resetToken;
    }
}
