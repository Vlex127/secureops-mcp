import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class App {
    private static final String DB_PASSWORD = "super_secret_db_pass_12345";

    public void unsafeQuery(Connection conn, String userInput) {
        try {
            String query = "SELECT * FROM users WHERE id = '" + userInput + "'";
            Statement stmt = conn.createStatement();
            stmt.execute(query);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        String url = "jdbc:postgresql://10.0.0.1:5432/production";
        Connection conn = DriverManager.getConnection(url, "admin", DB_PASSWORD);
        App app = new App();
        app.unsafeQuery(conn, args[0]);
    }
}
