import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class JdbcSqlInjectionTest {

	private static final String connectionUrl = "jdbc:hsqldb:mem://test";
	private Connection connection;
	private String injectedSql = "' OR 1=1 UNION SELECT t.TABLE_NAME FROM INFORMATION_SCHEMA.TABLES AS t -- ";

	@Before
	public void setup() throws SQLException {
		connection = DriverManager.getConnection(connectionUrl, "sa", "sa");
		// drop + create table
		String sql = "DROP TABLE IF EXISTS articles";
		connection.createStatement().executeQuery(sql);
		sql = "CREATE TABLE articles (id INTEGER IDENTITY PRIMARY KEY, text VARCHAR(64))";
		connection.createStatement().executeQuery(sql);
		// add some data
		String insert = "INSERT INTO articles (text) VALUES ('Der Artikel'), ('An article'), ('ein bisschen Text')";
		connection.createStatement().executeUpdate(insert);
	}

	@Test
	@Ignore
	public void successfulSqlnjection() throws Exception {
		// 'normal' query
		String harmlessSearchPhrase = "Artikel";
		List<String>  extractedData = queryWithVulnerableSql(harmlessSearchPhrase);
		extractedData.stream().forEach(data -> System.out.println(data)); 
		Assert.assertSame(1, extractedData.size());
		
		// evil query, will print all available tables in database
		extractedData = queryWithVulnerableSql(injectedSql);
		extractedData.stream().forEach(data -> System.out.println(data)); 
		// 97 tables should be shown as union with the 'normal' result
		// Kaboom, sql injected !
		Assert.assertSame(97, extractedData.size());
	}
	
	@Test
	public void failingSqlInjection() throws SQLException {
		// 'normal' query
		String harmlessSql = "Artikel";
		List<String>  extractedData = queryWithSafeSql(harmlessSql);
		extractedData.stream().forEach(data -> System.out.println(data)); 
		Assert.assertSame(1, extractedData.size());

		// attempt to inject an evil query
		String evilSql = "' OR 1=1 UNION SELECT t.TABLE_NAME FROM INFORMATION_SCHEMA.TABLES AS t -- ";
		extractedData = queryWithSafeSql(evilSql);
		extractedData.stream().forEach(data -> System.out.println(data)); 
		// nothing will be extracted, sql injection has been prevented
		Assert.assertTrue(extractedData.isEmpty());
	}
	
	/**
	 * Not using PreparedStatement for parameterized queries will allow sql injection
	 */
	public List<String> queryWithVulnerableSql(String find) throws SQLException {
		String sql = "SELECT text FROM articles WHERE text LIKE '%"+ find +"%'";
		ResultSet rs = connection.createStatement().executeQuery(sql);
		List<String> matches = new ArrayList<>();
		System.out.println(sql + " returns: ");
		while(rs.next()) {
			String text = rs.getString("text");
			matches.add(text);
		}
		return matches;
	}
	
	/**
	 * Using PreparedStatement will prevent from sql injection attempt
	 */
	public List<String> queryWithSafeSql(String find) throws SQLException {
		String sql = "SELECT text FROM articles WHERE text LIKE ?";
		PreparedStatement ps = connection.prepareStatement(sql);
		ps.setString(1, "%"+ find +"%");
		ResultSet rs = ps.executeQuery();
		List<String> matches = new ArrayList<>();
		System.out.println(ps + " returns: ");
		while(rs.next()) {
			String text = rs.getString("text");
			matches.add(text);
		}
		return matches;
	}
	
}
