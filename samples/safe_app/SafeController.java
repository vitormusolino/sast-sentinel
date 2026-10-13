// Mesmos cenários do UserController, implementados corretamente (nenhum achado esperado).
package demo;

import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.*;
import javax.crypto.Cipher;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

@RestController
public class SafeController {
    private static final String DB_PASSWORD_ENV = "DB_PASSWORD";
    private final String dbPassword = System.getenv(DB_PASSWORD_ENV);
    private Connection conn;

    @GetMapping("/user")
    public String user(HttpServletRequest req) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, req.getParameter("id"));
        return ps.executeQuery().getString(1);
    }

    @GetMapping("/item")
    public String item(@RequestParam String id) throws Exception {
        int itemId = Integer.parseInt(id);
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM items WHERE id = " + itemId).getString(1);
    }

    @GetMapping("/ping")
    public String ping() throws Exception {
        new ProcessBuilder("ping", "-c", "1", "127.0.0.1").start();
        return "ok";
    }

    @GetMapping("/hello")
    public void hello(@RequestParam String name, HttpServletResponse resp) throws Exception {
        resp.getWriter().println("Olá " + HtmlUtils.htmlEscape(name));
    }

    public byte[] hash(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    public Cipher cipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    public byte[] token() {
        byte[] token = new byte[32];
        new SecureRandom().nextBytes(token);
        return token;
    }
}
